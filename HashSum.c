/* Compute and validate checksums of files.
 *
 * Copyright (C) 2017-2023 Mark Pizzolato.
 * All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Written by Mark Pizzolato <mark@infocomm.com>
 *
 * All of the ideas implemented here are derived from the *nix programs:
 * md5sum, sha1sum, sha256sum, sha512sum, etc. and are intended to provide
 * equivalent funcdtionality to these programs on a Windows platform.
 *
 */

/* Written by Mark Pizzolato <mark@infocomm.com>.  */

#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <io.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <Windows.h>
#include <bcrypt.h>
#include <Winternl.h>

#pragma comment(lib, "bcrypt.lib")

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ERROR_SUCCESS
#endif

#define VERSION "2.0RC2"

#define FLG_CHECK   0X0001
#define FLG_QUIET   0X0002
#define FLG_STATUS  0X0004
#define FLG_WARN    0X0008
#define FLG_STRICT  0X0010
#define FLG_BINARY  0X0020
#define FLG_TEXT    0X0040
#define FLG_BSDTAG  0X0080
#define FLG_IGNORE  0X0100
#define FLG_ZERO    0X0200
#define FLG_RECURSE 0X0400
#define FLG_CMDARG  0X0800

#define MIN(a,b) ((a<b) ? (a) : (b))

const char *
GetErrorText(DWORD dwError)
    {
    static char szMsgBuffer[2048];
    DWORD dwStatus;

    dwStatus = FormatMessageA (FORMAT_MESSAGE_FROM_SYSTEM|
                               FORMAT_MESSAGE_IGNORE_INSERTS,     //  __in      DWORD dwFlags,
                               NULL,                              //  __in_opt  LPCVOID lpSource,
                               dwError,                           //  __in      DWORD dwMessageId,
                               0,                                 //  __in      DWORD dwLanguageId,
                               szMsgBuffer,                       //  __out     LPTSTR lpBuffer,
                               sizeof (szMsgBuffer) -1,           //  __in      DWORD nSize,
                               NULL);                             //  __in_opt  va_list *Arguments
    if (0 == dwStatus)
        {
        typedef DWORD (__stdcall *_func)();
        _func func_ptr = (_func)GetProcAddress(GetModuleHandleA("Ntdll.dll"), "RtlNtStatusToDosError");

        dwStatus = FormatMessageA (FORMAT_MESSAGE_FROM_SYSTEM|
                                   FORMAT_MESSAGE_IGNORE_INSERTS,     //  __in      DWORD dwFlags,
                                   NULL,                              //  __in_opt  LPCVOID lpSource,
                                   func_ptr(dwError),                 //  __in      DWORD dwMessageId,
                                   0,                                 //  __in      DWORD dwLanguageId,
                                   szMsgBuffer,                       //  __out     LPTSTR lpBuffer,
                                   sizeof (szMsgBuffer) -1,           //  __in      DWORD nSize,
                                   NULL);                             //  __in_opt  va_list *Arguments
        if (0 == dwStatus)
            _snprintf(szMsgBuffer, sizeof(szMsgBuffer) - 1, "Error Code: 0x%lX", dwError);
        }
    while (isspace (szMsgBuffer[strlen (szMsgBuffer)-1]))
        szMsgBuffer[strlen (szMsgBuffer) - 1] = '\0';
    return szMsgBuffer;
    }

const char *
GetProgramBaseName()
    {
    char FullName[MAX_PATH + 1];
    static char BaseName[_MAX_FNAME + 1];

    if (GetModuleFileNameA(NULL, FullName, sizeof(FullName)) >= sizeof(FullName))
        return "";
    if (_splitpath_s(FullName, NULL, 0, NULL, 0, BaseName, sizeof(BaseName), NULL, 0))
        return "";
    return BaseName;
    }

SSIZE_T
GetLine(char **pBuf, size_t *pBufSize, FILE *file)
    {
    char chunk[1024];
    size_t chunk_size;
    size_t buf_used = 0;

    if (pBuf == NULL)
        {
        errno = EINVAL;
        return -1;
        }
    if (ferror(file) || feof(file))
        return -1;
    do {
        if (chunk != fgets(chunk, sizeof(chunk), file))
            strcpy(chunk, "");
        chunk_size = strlen(chunk);
        if (*pBufSize < chunk_size + 1)
            {
            char *newbuf = (char *)realloc(*pBuf, *pBufSize + chunk_size + 1);

            if (newbuf == NULL)
                return -1;
            *pBuf = newbuf;
            *pBufSize += chunk_size + 1;
            }
        memcpy(*pBuf + buf_used, chunk, chunk_size + 1);
        buf_used += chunk_size;
        } while ((chunk_size != 0) && (chunk[chunk_size - 1] != '\n'));
    return buf_used;
    }

void
CloseHashAlgorithmProvider(BCRYPT_ALG_HANDLE hAlg)
    {
    if (hAlg != INVALID_HANDLE_VALUE)
        BCryptCloseAlgorithmProvider(hAlg, 0);
    }

BCRYPT_ALG_HANDLE
OpenHashAlgorithmProvider(const char *Algorithm)
    {
    BCRYPT_ALG_HANDLE hAlg = INVALID_HANDLE_VALUE;
    NTSTATUS result;
    wchar_t AlgorithmW[65];
    DWORD cbHash, cbData;
    size_t i;

    memset(AlgorithmW, 0, sizeof(AlgorithmW));
    for (i=0; (i<64) && (Algorithm[i] != '\0'); i++)
        AlgorithmW[i] = Algorithm[i];
    result = BCryptOpenAlgorithmProvider(&hAlg,     // algorithm handle
                                         AlgorithmW,// hashing algorithm ID
                                         NULL,      // use default provider
                                         0);        // default flags
    if (STATUS_SUCCESS != result)
        {
        fprintf(stderr, "Can't load '%s' cryptographic algorithm provider: %s\n", Algorithm, GetErrorText(result));
        hAlg = INVALID_HANDLE_VALUE;
        }
    else
        {
        result = BCryptGetProperty(hAlg, 
                                   BCRYPT_HASH_LENGTH, 
                                   (PBYTE)&cbHash, 
                                   sizeof(cbHash), 
                                   &cbData, 
                                   0);
        if (STATUS_SUCCESS != result)
            {
            fprintf(stderr, "cryptographic algorithm provider '%s' does not provide hash functionality:\n %s\n", Algorithm, GetErrorText(result));
            CloseHashAlgorithmProvider(hAlg);
            hAlg = INVALID_HANDLE_VALUE;
            }
        }
    return hAlg;
    }

#if 0
/* TexInfo description */
`-b'
`--binary'
     Treat each input file as binary, by reading it in binary mode and
     outputting a `*' flag.  This is the inverse of `--text'.  On
     systems like GNU that do not distinguish between binary and text
     files, this option merely flags each input mode as binary: the MD5
     checksum is unaffected.  This option is the default on Windows
     systems since they distinguish between binary and text files, except
     for reading standard input when standard input is a terminal.

`-c'
`--check'
     Read file names and checksum information (not data) from each FILE
     (or from stdin if no FILE was specified) and report whether the
     checksums match the contents of the named files.  The input to
     this mode of the program is usually the output of a prior,
     checksum-generating run of the program.  Each valid line of input
     consists of an checksum, a binary/text flag, and then a file
     name.  Binary mode is indicated with `*', text with ` ' (space).
     For each such line, the program reads the named file and computes its
     checksum.  Then, if the computed message digest does not match
     the one on the line with the file name, the file is noted as having
     failed the test.  Otherwise, the file passes the test.  By
     default, for each valid line, one line is written to standard
     output indicating whether the named file passed the test.  After
     all checks have been performed, if there were any failures, a
     warning is issued to standard error.  Use the `--status' option to
     inhibit that output.  If any listed file cannot be opened or read,
     if any valid line has a checksum inconsistent with the associated 
     file, or if no valid line is found, the program exits with
     nonzero status.  Otherwise, it exits successfully.

`--quiet'
     This option is useful only when verifying checksums.  When
     verifying checksums, don't generate an 'OK' message per
     successfully checked file.  Files that fail the verification are
     reported in the default one-line-per-file format.  If there is any
     checksum mismatch, print a warning summarizing the failures to
     standard error.

`--status'
     This option is useful only when verifying checksums.  When
     verifying checksums, don't generate the default one-line-per-file
     diagnostic and don't output the warning summarizing any failures.
     Failures to open or read a file still evoke individual diagnostics
     to standard error.  If all listed files are readable and are
     consistent with the associated MD5 checksums, exit successfully.
     Otherwise exit with a status code indicating there was a failure.

`--tag'
     Output BSD style checksums, which indicate the checksum algorithm
     used.  As a GNU extension, file names with problematic characters
     are escaped as described above, with the same escaping indicator
     of `\' at the start of the line, being used.  The `--tag' option
     implies binary mode, and is disallowed with `--text' mode as
     supporting that would unnecessarily complicate the output format,
     while providing little benefit.

`-t'
`--text'
     Treat each input file as text, by reading it in text mode and
     outputting a ` ' flag.  This is the inverse of `--binary'.  This
     option is the default on systems like GNU that do not distinguish
     between binary and text files.  On other systems, it is the
     default for reading standard input when standard input is a
     terminal.  This mode is never defaulted to if `--tag' is used.

`--auto'
     Dynamically determine if the input file(s) are text or binary 
     on the fly.  Files with CRLF line endings are teated as text
     and adjusted to LF line endings as they are processed.

‘-z’
‘--zero’
     Output a zero byte (ASCII NUL) at the end of each line, rather than
     a newline.  This option enables other programs to parse the output
     even when that output might contain data with embedded newlines.

'-r'
‘--recurse
     Scan for the specified file(s) in all subdirectories of the 
     specified directory (or the current directory) to checksum.

`-w'
`--warn'
     When verifying checksums, warn about improperly formatted 
     checksum lines.  This option is useful only if all but a few lines
     in the checked input are valid.

`--strict'
     When verifying checksums, if one or more input line is invalid,
     exit nonzero after all warnings have been issued.


   An exit status of zero indicates success, and a nonzero value
indicates failure.

SHA1,SHA256,SHA384,SHA512 "FIPS-180-4"
MD5 "RFC 1321"
MD4 "RFC 1320"
MD2 "RFC 1319"
AES-GMAC "RFC 4543"
AES-CMAC "RFC 4493"
#endif

void
Usage (const char *AlgorithmName)
    {
    size_t i;
    char CommandString[MAX_PATH+1];
    char *Algorithms = NULL;
    DWORD cbHash, cbData, cbAlgCount;
    BCRYPT_ALGORITHM_IDENTIFIER *pAlgList = NULL;
    NTSTATUS result;
    BCRYPT_ALG_HANDLE hAlg = OpenHashAlgorithmProvider(AlgorithmName);

    if (!strcmp("hashsum", GetProgramBaseName()))
        _snprintf(CommandString, sizeof(CommandString)-1, "%s -a:%s", GetProgramBaseName(), AlgorithmName);
    else
        strncpy(CommandString, GetProgramBaseName(), sizeof(CommandString)-1);
    if (hAlg != INVALID_HANDLE_VALUE)
        {
        BCryptGetProperty(hAlg, 
                          BCRYPT_HASH_LENGTH, 
                          (PBYTE)&cbHash, 
                          sizeof(cbHash), 
                          &cbData, 
                          0);
        CloseHashAlgorithmProvider(hAlg);
        }
    if (hAlg == INVALID_HANDLE_VALUE)
        {
        result = BCryptEnumAlgorithms(BCRYPT_HASH_OPERATION,
                                      &cbAlgCount,
                                      &pAlgList,
                                      0);
        if (STATUS_SUCCESS == result)
            {
            for (i=0; i<cbAlgCount; i++)
                {
                char AlgorithmName[64];
                size_t j;

                memset(AlgorithmName, 0, sizeof(AlgorithmName));
                for (j=0; (j<sizeof(AlgorithmName)) && (pAlgList[i].pszName[j]); j++)
                    AlgorithmName[j] = (char)pAlgList[i].pszName[j];
                hAlg = OpenHashAlgorithmProvider(AlgorithmName);
                if (hAlg != INVALID_HANDLE_VALUE)
                    {
                    size_t old_size = (Algorithms) ? strlen(Algorithms) : 0;

                    Algorithms = (char *)realloc(Algorithms, old_size + strlen(AlgorithmName) + 2);
                    sprintf(&Algorithms[old_size], "%s,", AlgorithmName);
                    CloseHashAlgorithmProvider(hAlg);
                    }
                }
            Algorithms[strlen(Algorithms)-1] = '\0';
            }
        }
    fprintf(stdout, "\n");
    fprintf(stdout,
"%s(1)                     User Commands                    %s(1)\n"
"\n"
"NAME\n"
"       %s - compute and check %s message digests\n"
"\n",
GetProgramBaseName(), GetProgramBaseName(), CommandString, AlgorithmName);
    fprintf(stdout,
"SYNOPSIS\n"
"       %s [OPTION]... [FILE]...\n"
"\n"
"DESCRIPTION\n"
"       Print  or check %s (%u-bit) checksums.  With no FILE, or when FILE\n",
CommandString, AlgorithmName, cbHash*8);
    fprintf(stdout,
"       is -, read standard input.\n"
"\n"
"       -b, --binary\n"
"             read in binary mode\n"
"\n"
"       -c, --check\n"
"             read checksums from the FILEs and check them\n"
"\n"
"       --tag create a BSD-style checksum\n"
"\n"
"       -t, --text\n"
"             read in text mode\n"
"\n"
"       --auto\n"
"             determine text or binary on the fly when creating a\n"
"             new checksum.  Files with CRLF line endings will be\n"
"             processed as text.\n"
"\n"
"       -z, --zero\n"
"            end each output line with NUL, not newline\n"
"\n"
"  -r, --recurse\n"
"            output checksums for all specified file(s) in all\n"
"            subdirectories.  This option is not meaningful when\n"
"            checking existing checksums (--check), and thus is\n"
"            ignored.\n"
"\n");
if (Algorithms)
    fprintf(stdout,
"       -a:HASH\n"
"              where HASH is one of these algorithms:\n"
"                %s\n", Algorithms);
    fprintf(stdout,
"\n"
"   The following three options are useful only when verifying checksums:\n"
"       --ignore-missing\n"
"              don't fail or report status for missing files\n"
"\n"
"       --quiet\n"
"              don't print OK for each successfully verified file\n"
"\n"
"       --status\n"
"              don't output anything, status code shows success\n"
"\n"
"       -w, --warn\n"
"              warn about improperly formatted checksum lines\n"
"\n"
"       --strict\n"
"              with --check, exit non-zero for any invalid input\n"
"\n"
"       --help display this help and exit\n"
"\n"
"       --version\n"
"              output version information and exit\n"
"\n"
"       The available checksum algorithms are computed as described in:\n"
"             SHA1,SHA256,SHA384,SHA512(FIPS-180-4)\n"
"             MD5(RFC 1321)\n"
"             MD4(RFC 1320)\n"
"             MD2(RFC 1319)\n"
"             AES-GMAC(RFC 4543)\n"
"             AES-CMAC(RFC 4493)\n"
"       When checking, the input should be a former output of this program or\n"
"       one of the *nix programs: md5sum, sha1sum, sha256sum, sha384sum or\n"
"       sha512sum.  The default mode is to print a line with checksum, a\n"
"       character indicating input  mode  ('*' for binary, space for text),\n"
"       and name for each FILE.\n"
"\n"
"AUTHOR\n"
"       Written by Mark Pizzolato.\n"
"\n"
"REPORTING BUGS\n"
"       Report %s bugs to mark@infocomm.com\n"
"\n"
"COPYRIGHT\n"
"       Copyright (c) 2017-2023 Mark Pizzolato.  All Rights Reserved.\n"
"       There is NO WARRANTY, to the extent permitted by law.\n"
"\n"
"\n",
GetProgramBaseName());
    fprintf(stdout,
"Usage: %s [OPTION]... [FILE]...\n",
CommandString);
if (cbHash)
    fprintf(stdout,
"Print or check %s (%u-bit) checksums.\n",
AlgorithmName, cbHash*8);
else
    fprintf(stdout,
"Print or check checksums.\n");
    fprintf(stdout,
"With no FILE, or when FILE is -, read standard input.\n"
"\n"
"  -b, --binary    read in binary mode\n"
"  -c, --check     read checksums from the FILEs and check them\n"
"      --tag       create a BSD-style checksum\n"
"  -t, --text      read in text mode\n"
"      --auto      read in text mode for files with CRLF line endings\n"
"  -z, --zero      end each output line with NUL, not newline\n"
"  -r, --recurse   checksum specified file(s) in all subdirectories\n");
if (Algorithms)
    fprintf(stdout,
"  -a:HASH         where HASH is one of these algorithms:\n"
"                     %s\n", Algorithms);
    fprintf(stdout,
"\n"
"The following five options are useful only when verifying checksums:\n"
"      --ignore-missing  don't fail or report status for missing files\n"
"      --quiet     don't print OK for each successfully verified file\n"
"      --status    don't output anything, status code shows success\n"
"      --strict    with --check, exit non-zero for any invalid input\n"
"  -w, --warn      warn about improperly formatted checksum lines\n"
"\n"
"      --help      display this help and exit\n"
"      --version   output version information and exit\n"
"\n"
"When checking, the input should be a former output of this program or one\n"
"of the *nix programs: md5sum, sha1sum, sha256sum, sha384sum, sha512sum.\n"
"The available checksum algorithms are computed as described in:\n"
"        SHA1,SHA256,SHA384,SHA512(FIPS-180-4)\n"
"        MD5(RFC 1321)\n"
"        MD4(RFC 1320)\n"
"        MD2(RFC 1319)\n"
"        AES-GMAC(RFC 4543)\n"
"        AES-CMAC(RFC 4493)\n"
"The default mode is to print a line with checksum, a character indicating\n"
"input mode ('*' for binary, space for text), and name for each FILE.\n"
"\n"
"Report %s bugs to mark@infocomm.com\n", GetProgramBaseName());
    free(Algorithms);
    exit(EXIT_FAILURE);
    }

int
GetFileHash(BCRYPT_ALG_HANDLE hAlg, FILE *file, char **hash)
    {
    NTSTATUS result;
    BCRYPT_HASH_HANDLE hHash  = NULL;
    DWORD cbData, cbHashObject, cbHash, i;
    PBYTE pbHashObject        = NULL;
    PBYTE pbHash              = NULL;
    const char HexDigits[]    = "0123456789abcdef";
    char FileBuf[32768];

    *hash = NULL;
    result = BCryptGetProperty(hAlg, 
                               BCRYPT_OBJECT_LENGTH, 
                               (PBYTE)&cbHashObject, 
                               sizeof(cbHashObject), 
                               &cbData, 
                               0);
    if (STATUS_SUCCESS != result)
        {
        fprintf(stderr, "**** Error BCryptGetProperty Returned: %s\n", GetErrorText(result));
        goto Cleanup;
        }

    //allocate the hash object on the heap
    pbHashObject = (PBYTE)malloc(cbHashObject);
    if(NULL == pbHashObject)
        {
        fprintf(stderr, "**** memory allocation failed\n");
        goto Cleanup;
        }

   //calculate the length of the hash
    result = BCryptGetProperty(hAlg, 
                               BCRYPT_HASH_LENGTH, 
                               (PBYTE)&cbHash, 
                               sizeof(cbHash), 
                               &cbData, 
                               0);
    if (STATUS_SUCCESS != result)
        {
        fprintf(stderr, "**** Error BCryptGetProperty Returned: %s\n", GetErrorText(result));
        goto Cleanup;
        }

    //allocate the hash buffer on the heap
    pbHash = (PBYTE)malloc(cbHash);
    if(NULL == pbHash)
        {
        fprintf(stderr, "**** memory allocation failed\n");
        goto Cleanup;
        }

    //create a hash
    result = BCryptCreateHash(hAlg, 
                              &hHash, 
                              pbHashObject, 
                              cbHashObject, 
                              NULL, 
                              0, 
                              0);
    if (STATUS_SUCCESS != result)
        {
        fprintf(stderr, "**** Error BCryptCreateHash Returned: %s\n", GetErrorText(result));
        goto Cleanup;
        }    

    //hash file data
    while (!feof(file))
        {
        size_t bytes = fread(FileBuf, 1, sizeof(FileBuf), file);

        if (bytes == 0)
            break;

        result = BCryptHashData(hHash,
                                (PBYTE)FileBuf,
                                bytes,
                                0);
        if (STATUS_SUCCESS != result)
            {
            fprintf(stderr, "**** Error BCryptHashData Returned: %s\n", GetErrorText(result));
            goto Cleanup;
            }
        }

    //close the hash
    result = BCryptFinishHash(hHash, 
                              pbHash, 
                              cbHash, 
                              0);
    if (STATUS_SUCCESS != result)
        {
        fprintf(stderr, "**** Error BCryptFinishHash Returned: %s\n", GetErrorText(result));
        goto Cleanup;
        }

    if (feof(file) && (!ferror(file)))
        {
        *hash = (char *)calloc(2*cbHash+1, sizeof(*hash));
        for (i=0; i<cbHash; i++)
            {
            (*hash)[2 * i] = HexDigits[(pbHash[i] >> 4) & 0xF];
            (*hash)[2 * i + 1] = HexDigits[pbHash[i] & 0xF];
            }
        }

Cleanup:

    if (hHash)    
        BCryptDestroyHash(hHash);

    if (pbHashObject)
        free(pbHashObject);
    if (pbHash)
        free(pbHash);
    return (*hash == NULL) ? EXIT_FAILURE : EXIT_SUCCESS;
    }

int
ClassifyFileContents(FILE *f, const char **mode)
    {
    unsigned char FileBuf[65536 + 1];
    size_t bytes, byte, lfcount = 0, crlfcount = 0;

    *mode = "rb";
    _setmode(fileno(f), _O_BINARY);
    FileBuf[sizeof(FileBuf)-1] = '\0';
    bytes = fread(FileBuf, 1, sizeof(FileBuf) - 1, f);
    for (byte=0; byte<bytes; byte++) 
        {
        switch (FileBuf[byte])
            {
            case '\n':
                ++lfcount;
                break;
            case '\r':
                if (FileBuf[byte+1] == '\n')
                    ++crlfcount;
                break;
            default:
                if ((FileBuf[byte] > 127) || (!isprint(FileBuf[byte])))
                    break;
                break;
            }
        }
    rewind(f);
    if ((byte == bytes) &&      /* No binary data && */
        (lfcount == crlfcount)) /* CRLF line endings */
        {
        _setmode(fileno(f), _O_TEXT);
        *mode = "rt";
        return 1;               /* return Text Mode */
        }
    return 0;                   /* Return Binary Mode */
    }

int
GetFileTextOrBinaryMode(const char *file, const char **mode)
    {
    int return_status = -1;
    FILE *f;

    *mode = "rb";
    f = fopen(file, *mode);
    if (NULL != f)
        {
        return_status = ClassifyFileContents(f, mode);
        fclose(f);
        }
    return return_status;
    }

int
ParseSumLine(char *line, size_t size, char **hash, char **file, char **open_mode, char **algo)
    {
    char *c;
    size_t file_len;
    char *rparen = strstr(line, ") = ");
    char *lparen = strstr(line, " (");
    static const char HashChars[] = "0123456789abcdefABCDEF\r\n";
    size_t i;

    if (lparen && rparen && (lparen < rparen))  /* BSD format line? */
        {
        /* Validate hash data as all hex */
        c = rparen + 4;
        for (i=0; i<strlen(c); i++)
            if (NULL == strchr(HashChars, c[i]))
                break;
        if (i == strlen(c))
            {
            *algo = line;
            *file = lparen + 2;
            *hash = rparen + 4;
            *lparen = *rparen = '\0';
            *open_mode = "rb";
            /* Remove trailing newline from hash string */
            if ((*hash)[strlen(*hash)-1] == '\n')
                {
                (*hash)[strlen(*hash)-1] = '\0';
                if ((*hash)[strlen(*hash)-1] == '\r')
                    (*hash)[strlen(*hash)-1] = '\0';
                }
            /* Make sure hash hex text is lower case */
            for (i=0; i<strlen(*hash); i++)
                if (isupper(c[i]))
                    c[i] = tolower(c[i]);
            return EXIT_SUCCESS;
            }
        }
    *hash = line;
    if (NULL == (c = strchr(line, ' ')))
        return EXIT_FAILURE;
    *c++ = '\0';
    /* Make sure hash hex text is lower case */
    for (i=0; i<strlen(*hash); i++)
        {
        if (NULL == strchr(HashChars, line[i]))
            return EXIT_FAILURE;
        if (isupper(line[i]))
            line[i] = tolower(line[i]);
        }
    if ((*c != '*') && (*c != ' '))
        return EXIT_FAILURE;
    *open_mode = (*c++ == '*') ? "rb" : "rt";
    *file = c;
    /* Remove trailing newline from filename */
    file_len = strlen(*file);
    if ((file_len) && (c[file_len-1] == '\n'))
        c[--file_len] = '\0';
    if ((file_len) && (c[file_len-1] == '\r'))
        c[--file_len] = '\0';
    *algo = NULL;
    if (strcmp("rt", *open_mode) == 0)
        GetFileTextOrBinaryMode(c, open_mode);
    return EXIT_SUCCESS;
    }

int
ProcessFile(BCRYPT_ALG_HANDLE hAlg, const char *file, int flags)
    {
    int status;
    FILE *f;
    char *open_mode = (flags & FLG_TEXT) ? "rt" : "rb";
    char *hash = NULL;
    wchar_t AlgorithmNameW[32];
    char AlgorithmName[sizeof(AlgorithmNameW)];
    size_t i;
    struct _stat64 statb;
    DWORD cbData;

    if (strcmp("-", file))
        {
        int return_status = EXIT_SUCCESS;
        char DirName[MAX_PATH + 1] = "";
        char FileName[MAX_PATH + 1] = "";
        char WildName[MAX_PATH + 1];
        const char *backslash = strrchr (file, '\\');
        const char *slash = strrchr (file, '/');
        const char *pathsep = (backslash && slash) ? MIN (backslash, slash) : (backslash ? backslash : slash);
        const char *c;

        if (pathsep == NULL)                        /* Separator wasn't mentioned? */
            pathsep = "\\";                         /* Default to Windows backslash */
        c = strrchr(file, *pathsep);
        if (c != NULL)
            {   /* Separate Directory Path from FileName */
            memcpy(DirName, file, 1 + c - file);
            DirName[2 + c - file] = '0';
            strncpy(FileName, c + 1, sizeof(FileName));
            }
        else
            strncpy(FileName, file, sizeof(FileName));
        if (*pathsep == '/')                        /* If slash separator? */
            {
            char *c;

            while ((c = strchr (DirName, '\\')))
                *c = '/';                           /* Convert backslash to slash */
            }
        if (islower (DirName[0]) && (DirName[1] == ':'))
            DirName[0] = toupper (DirName[0]);
        if (((c != NULL) && ((strchr(c + 1, '*') != NULL) || (strchr(c + 1, '?') != NULL))) ||
            ((strchr(file, '*') != NULL) || (strchr(file, '?') != NULL)))
            {
            HANDLE hFind;
            WIN32_FIND_DATAA File;

            strcpy(WildName, FileName);
            /* Handle Wildcards in file name */
            if ((hFind = FindFirstFileA (file, &File)) != INVALID_HANDLE_VALUE) 
                {
                do 
                    {
                    if ((strcmp(File.cFileName, ".") == 0) ||
                        (strcmp(File.cFileName, "..") == 0))
                        continue;
                    _snprintf(FileName, sizeof(FileName), "%s%s", DirName, File.cFileName);
                    if (_stat64(FileName, &statb))
                        {
                        fprintf(stderr, "Can't stat '%s': %s\n", FileName, strerror(errno));
                        return_status = EXIT_FAILURE;
                        continue;
                        }
                    if (statb.st_mode&_S_IFDIR)
                        {
                        if ((flags & FLG_RECURSE) == 0)
                            fprintf(stderr, "%s: %s: Is a directory\n", GetProgramBaseName(), FileName);
                        continue;
                        }
                    status = ProcessFile(hAlg, FileName, flags & ~(FLG_RECURSE | FLG_CMDARG));
                    if (status)
                        return_status = status;
                    } while (FindNextFileA(hFind, &File));
                FindClose(hFind);
                }
            if (flags & FLG_RECURSE)
                {
                char WildPath[MAX_PATH + 1];
                char DirPath[MAX_PATH + 1];

                _snprintf(WildPath, sizeof(WildPath), "%s*", DirName);
                if ((hFind = FindFirstFileA (WildPath, &File)) != INVALID_HANDLE_VALUE) 
                    {
                    char DirFile[MAX_PATH + 1];

                    do 
                        {
                        if ((strcmp(File.cFileName, ".") == 0) ||
                            (strcmp(File.cFileName, "..") == 0))
                            continue;
                        _snprintf(DirFile, sizeof(DirFile), "%s%s", DirName, File.cFileName);
                        if (_stat64(DirFile, &statb))
                            {
                            fprintf(stderr, "Can't stat '%s': %s\n", DirFile, strerror(errno));
                            return_status = EXIT_FAILURE;
                            continue;
                            }
                        if ((statb.st_mode&_S_IFDIR) == 0)
                            continue;
                        /* Look for the wildcard pattern in this subdirectory */
                        _snprintf(DirPath, sizeof(DirPath), "%s%s%c%s", DirName, File.cFileName, *pathsep, WildName);
                        status = ProcessFile(hAlg, DirPath, flags & ~FLG_CMDARG);
                        if (status)
                            return_status = status;
                        } while (FindNextFileA(hFind, &File));
                    FindClose(hFind);
                    }
                }
            return return_status;   /* Done with this wildcard pattern in current directory */
            }
        if (_stat64(file, &statb))
            {
            fprintf(stderr, "Can't stat '%s': %s\n", file, strerror(errno));
            return EXIT_FAILURE;
            }
        if (statb.st_mode&_S_IFDIR)
            {
            if (flags & FLG_CMDARG)
                {
                _snprintf(WildName, sizeof(WildName), "%s%s%c*", DirName, FileName, *pathsep);
                return ProcessFile(hAlg, WildName, flags & ~FLG_CMDARG);
                }
            else
                {
                if (flags & FLG_RECURSE)
                    {
                    fprintf(stderr, "%s: %s: Is a directory\n", GetProgramBaseName(), file);
                    return EXIT_FAILURE;
                    }
                }
            }
        }
    memset(AlgorithmNameW, 0, sizeof(AlgorithmNameW));
    BCryptGetProperty(hAlg, 
                      BCRYPT_ALGORITHM_NAME, 
                      (PBYTE)AlgorithmNameW, 
                      sizeof(AlgorithmNameW), 
                      &cbData, 
                      0);
    for (i=0; i<sizeof(AlgorithmNameW); i++)
        AlgorithmName[i] = (char)AlgorithmNameW[i];
    if (!strcmp("-", file))
        {
        DWORD Mode;

        if ((GetStdHandle (STD_INPUT_HANDLE)) && 
            (GetStdHandle (STD_INPUT_HANDLE) != INVALID_HANDLE_VALUE) && 
            GetConsoleMode (GetStdHandle (STD_INPUT_HANDLE), &Mode))
            flags &= ~FLG_BINARY;
        else
            flags |= FLG_BINARY;
        fprintf(stderr, "%s mode _setmode for stdin\n", (flags & FLG_BINARY) ? "Binary" : "Text");
        _setmode(fileno(stdin), (flags & FLG_BINARY) ? _O_BINARY : _O_TEXT);
        f = stdin;
        }
    else
        f = fopen(file, open_mode);
    if (NULL == f)
        {
        fprintf(stderr, "Error Opening '%s': %s\n", file, strerror(errno));
        return EXIT_FAILURE;
        }
    if (flags & FLG_CHECK)
        {
        char *line_buf = NULL;
        size_t line_buf_size = 0;
        SSIZE_T line_size;
        size_t line_number = 0;
        int mis_matches = 0;
        int matches = 0;
        int bad_lines = 0;
        int open_or_io_errors = 0;
        BCRYPT_ALG_HANDLE hCheckAlg = INVALID_HANDLE_VALUE;

#define LINE_CLEANUP                                \
    do                                              \
        {                                           \
        if (check != stdin)                         \
            fclose(check);                          \
        if (hCheckAlg != INVALID_HANDLE_VALUE)      \
            {                                       \
            CloseHashAlgorithmProvider(hCheckAlg);  \
            hCheckAlg = INVALID_HANDLE_VALUE;       \
            }                                       \
        free(file_hash);                            \
        } while (0)

        while (0 < (line_size = GetLine(&line_buf, &line_buf_size, f)))
            {
            char *file_hash;
            char *hash;
            char *file;
            char *algo;
            char *open_mode;
            int line_stat;
            FILE *check;

            ++line_number;
            line_stat = ParseSumLine(line_buf, line_size, &hash, &file, &open_mode, &algo);
            if (line_stat != EXIT_SUCCESS)
                {
                ++bad_lines;
                status = line_stat;
                continue;               /* Next line */
                }
            if (!strcmp("-", file))
                {
                DWORD Mode;

                _setmode(fileno(stdin), ((GetStdHandle (STD_INPUT_HANDLE)) && 
                                        (GetStdHandle (STD_INPUT_HANDLE) != INVALID_HANDLE_VALUE) && 
                                        GetConsoleMode (GetStdHandle (STD_INPUT_HANDLE), &Mode)) ? _O_TEXT : _O_BINARY);
                check = stdin;
                }
            else
                {
                if (NULL == (check = fopen(file, open_mode)))
                    {
                    if ((flags & FLG_IGNORE) && (errno == ENOENT))
                        continue;       /* Next line */
                    ++open_or_io_errors;
                    fprintf(stderr, "%s: Error Opening '%s': %s\n", GetProgramBaseName(), file, strerror(errno));
                    continue;           /* Next line */
                    }
                }
            if (algo && (strcmp(algo, AlgorithmName)))
                {
                hCheckAlg = OpenHashAlgorithmProvider(algo);
                if (hCheckAlg == INVALID_HANDLE_VALUE)
                    {
                    fprintf(stderr, "%s: Unknown Algorithm Type: %s, can't check %s\n", GetProgramBaseName(), algo, file);
                    fclose(check);
                    status = EXIT_FAILURE;
                    continue;           /* Next line */
                    }
                }
            line_stat = GetFileHash((algo && (hCheckAlg != INVALID_HANDLE_VALUE)) ? hCheckAlg : hAlg, check, &file_hash);
            if (line_stat != EXIT_SUCCESS)
                {
                LINE_CLEANUP;
                ++open_or_io_errors;
                status = line_stat;
                free(file_hash);
                continue;               /* Next line */
                }
            if (strcmp(file_hash, hash))
                {
                if (strchr(open_mode, 't') != NULL)
                    {
                    /* Text mode failed, try again in binary mode */
                    open_mode = "rb";
                    rewind(check);
                    _setmode(fileno(check), _O_BINARY);
                    free(file_hash);
                    line_stat = GetFileHash((algo && (hCheckAlg != INVALID_HANDLE_VALUE)) ? hCheckAlg : hAlg, check, &file_hash);
                    if (strcmp(file_hash, hash))
                        {
                        /* binary mode failure */
                        status = EXIT_FAILURE;
                        ++mis_matches;
                        if (!(flags & FLG_QUIET))
                            fprintf(stdout, "%s: FAILED\n", file);
                        LINE_CLEANUP;
                        continue;       /* Next line */
                        }
                    }
                else
                    {
                    /* binary mode failure */
                    status = EXIT_FAILURE;
                    ++mis_matches;
                    if (!(flags & FLG_QUIET))
                        fprintf(stdout, "%s: FAILED\n", file);
                    LINE_CLEANUP;
                    continue;           /* Next line */
                    }
                }
            LINE_CLEANUP;
            ++matches;
            if (!(flags & FLG_QUIET))
                fprintf(stdout, "%s: OK\n", file);
            }
        if (!(flags & FLG_STATUS))
            {
            if (bad_lines)
                fprintf(stderr, "%s: WARNING: %d line%s improperly formatted\n", GetProgramBaseName(), bad_lines, (bad_lines == 1) ? " is" : "s are");
            if (open_or_io_errors)
                fprintf(stderr, "%s: WARNING: %d listed file%s could not be read\n", GetProgramBaseName(), open_or_io_errors, (open_or_io_errors == 1) ? "" : "s");
            if (mis_matches)
                fprintf(stderr, "%s: WARNING: %d computed checksum%s did NOT match\n", GetProgramBaseName(), mis_matches, (mis_matches == 1) ? "" : "s");
            if ((mis_matches + matches) == 0)
                fprintf(stderr, "%s: %s: no file was verified\n", GetProgramBaseName(), file);
            }
        free(line_buf);
        }
    else
        {
        if ((flags & (FLG_BINARY | FLG_TEXT)) == 0)
            {                   /* No mode specified, auto detect text/binary files */
            fclose(f);
            f = fopen(file, "rb");
            if (NULL == f)
                {
                fprintf(stderr, "Error Opening '%s': %s\n", file, strerror(errno));
                return EXIT_FAILURE;
                }
            ClassifyFileContents(f, &open_mode);
            }
        status = GetFileHash(hAlg, f, &hash);
        if (hash)
            {
            if (flags & FLG_BSDTAG)
                {
                fprintf(stdout, "%s (", AlgorithmName);
                if (f == stdin)
                    fprintf(stdout, "-");
                else
                    {
                    size_t i;

                    for (i=0; i<strlen(file); i++)
                        fprintf(stdout, "%c", (file[i] == '\\') ? '/' : file[i]);
                    }
                fprintf(stdout, ") = %s", hash);
                }
            else
                {
                fprintf(stdout, "%s %s", hash, (strchr(open_mode, 't') == NULL) ? "*" : " ");
                if (f == stdin)
                    fprintf(stdout, "-");
                else
                    {
                    size_t i;

                    for (i=0; i<strlen(file); i++)
                        fprintf(stdout, "%c", (file[i] == '\\') ? '/' : file[i]);
                    }
                }
            if (flags & FLG_ZERO)
                fputc('\0', stdout);
            else
                fprintf(stdout, "\n");
            free(hash);
            hash = NULL;
            }
        }
    if (f != stdin)
        fclose(f);
    return status;
    }

wchar_t *
CharToWideChar(const char *string)
    {
    wchar_t *buf = (wchar_t *)calloc(1+strlen(string), sizeof(*buf));
    size_t i;

    for (i=0; i<strlen(string); i++)
        buf[i] = string[i];
    return buf;
    }

char *
GetAlgorithm (int argc, char **argv)
    {
    char *file;
    char *alg;
    size_t i;

    file = (char *)malloc(1+strlen(GetProgramBaseName()));
    strcpy(file, GetProgramBaseName());
    if ((strlen(file) > 3) &&
        (!stricmp("SUM", &file[strlen(file) - 3])))
        file[strlen(file) - 3] = '\0';

    if (!stricmp("HASH", file))
        {
        while (argc > 1)
            {
            if (!strncmp("-a:", argv[1], 3))
                {
                file = (char *)realloc(file, 1+strlen(&argv[1][3]));
                strcpy(file, &argv[1][3]);
                break;
                }
            --argc;
            ++argv;
            }
        }
    alg = (char *)calloc(1+strlen(file), sizeof(*alg));
    for (i=0; i<strlen(file); i++)
        alg[i] = islower(file[i]) ? toupper(file[i]) : file[i];
    free(file);
    return alg;
    }


void main(int                      argc, 
          __in_ecount(argc) char **argv)
    {
    BCRYPT_ALG_HANDLE hAlg = INVALID_HANDLE_VALUE;
    char *algorithm = GetAlgorithm(argc, argv);
    int files_processed = 0;
    int flags = FLG_BINARY;
    int status, exit_status = EXIT_SUCCESS;

    while (argc > 1)
        {
        --argc;
        ++argv;
        if (!strncmp("-a:", argv[0], 3))
            {
            size_t i;

            CloseHashAlgorithmProvider(hAlg);
            free(algorithm);
            algorithm = (char *)calloc(1+strlen(&argv[0][3]), sizeof(*algorithm));
            for (i=0; i<strlen(&argv[0][3]); i++)
                algorithm[i] = islower(argv[0][3+i]) ? toupper(argv[0][3+i]) : argv[0][3+i];
            hAlg = OpenHashAlgorithmProvider(algorithm);
            if (hAlg == INVALID_HANDLE_VALUE)
                {
                fprintf(stderr, "Unknown Algorithm Type: %s\n", algorithm);
                exit(EXIT_FAILURE);
                }
            continue;
            }
        if ((!strcmp("-b", argv[0])) || 
            (!strcmp("--binary", argv[0])))
            {
            flags |= FLG_BINARY;
            flags &= ~FLG_TEXT;
            continue;
            }
        if ((!strcmp("-c", argv[0])) || 
            (!strcmp("--check", argv[0])))
            {
            flags |= FLG_CHECK;
            flags &= ~FLG_RECURSE;
            continue;
            }
        if (!strcmp("--tag", argv[0]))
            {
            flags |= FLG_BSDTAG;
            flags |= FLG_BINARY;
            flags &= ~FLG_TEXT;
            continue;
            }
        if ((!strcmp("-t", argv[0])) || 
            (!strcmp("--text", argv[0])))
            {
            flags |= FLG_TEXT;
            flags &= ~FLG_BINARY;
            continue;
            }
        if (!strcmp("--auto", argv[0]))
            {
            flags &= ~(FLG_BINARY|FLG_TEXT);
            continue;
            }
        if ((!strcmp("-z", argv[0])) || 
            (!strcmp("--zero", argv[0])))
            {
            flags |= FLG_ZERO;
            continue;
            }
        if ((!strcmp("-r", argv[0])) || 
            (!strcmp("--recurse", argv[0])))
            {
            flags |= FLG_RECURSE;
            flags &= ~FLG_CHECK;
            continue;
            }
        if (!strcmp("--ignore-missing", argv[0]))
            {
            flags |= FLG_IGNORE;
            continue;
            }
        if (!strcmp("--quiet", argv[0]))
            {
            flags |= FLG_QUIET;
            continue;
            }
        if (!strcmp("--status", argv[0]))
            {
            flags |= FLG_STATUS;
            continue;
            }
        if ((!strcmp("-w", argv[0])) || 
            (!strcmp("--warn", argv[0])))
            {
            flags |= FLG_WARN;
            continue;
            }
        if (!strcmp("--strict", argv[0]))
            {
            flags |= FLG_STRICT;
            continue;
            }
        if ((!strcmp("--help", argv[0])) ||
            (!strcmp("/?", argv[0])))
            Usage(algorithm);
        if (!strcmp("--version", argv[0]))
            {
            fprintf(stdout, "%s Version %s", GetProgramBaseName(), VERSION);
            exit(EXIT_SUCCESS);
            }
        if ((argv[0][0] == '-') &&
            (strcmp("-", argv[0])))
            {
            fprintf(stderr, "%s: invalid option -- '%s'\n", GetProgramBaseName(), &argv[0][1]);
            fprintf(stderr, "try '%s --help' for more information\n", GetProgramBaseName());
            exit(EXIT_FAILURE);
            }
        if (hAlg == INVALID_HANDLE_VALUE)
            {
            hAlg = OpenHashAlgorithmProvider(algorithm);
            if (hAlg == INVALID_HANDLE_VALUE)
                {
                status = EXIT_FAILURE;
                break;
                }
            }
        status = ProcessFile(hAlg, argv[0], flags | FLG_CMDARG);
        if (status)
            exit_status = status;
        ++files_processed;
        }
    if (files_processed == 0)
        {
        if (hAlg == INVALID_HANDLE_VALUE)
            {
            hAlg = OpenHashAlgorithmProvider(algorithm);
            if (hAlg == INVALID_HANDLE_VALUE)
                exit_status = EXIT_FAILURE;
            }
        if (exit_status == EXIT_SUCCESS)
            exit_status = ProcessFile(hAlg, "-", flags | FLG_CMDARG);
        }
    CloseHashAlgorithmProvider(hAlg);
    free((void*)algorithm);
    exit(exit_status);
    }
