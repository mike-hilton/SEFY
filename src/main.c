/* main.c - Encrypt and decrypt files using asymmetric encryption  
 * 
 * DESCRIPTION:
 *      A small encryption/decryption utility based on Sodium (NaCl).
 *      It includes functionality that enables a user to generate a
 *      key pair and use it for encryption and decryption of files. 
 *      XSalsa20 is used for encryption/decryption and Poly1305 for data integrity (MAC).  
 * 
 * AUTHOR:      
 *      https://github.com/mike-hilton  
 * 
 * START DATE: 
 *      2019-04-16  
 * 
 */
#include <sodium.h>     // crypto_box_keypair, crypto_box_seal, crypto_box_seal_open, sodium_malloc, 
                        // sodium_base642bin, sodium_bin2base64, sodium_base64_ENCODED_LEN
#include <stdio.h>      // printf, fprintf, fgets, snprintf, fopen, fwrite, fread, ftell, rewind
#include <string.h>     // memset, strcpy, strlen, strcmp, strtok, strcat, strcspn
#include <stdlib.h>     // malloc, realloc, free, exit, 
#include <unistd.h>     // getopt, getopen, close, write, access, fstat, unlink, lseek
#include <libgen.h>     // basename
#include <getopt.h>
#include <errno.h>
#include <stdbool.h>
#include <sys/types.h>
#include <fcntl.h>
#include <sys/stat.h>

#define MAX_LEN_PATH (size_t) sysconf(_PC_PATH_MAX) // Including terminating null byte

/* Global variable declarations */
static char PROGRAM_NAME[5] = "sefy";           // Used to store the program's name
static char FILENAME_EXTENSION[6] = ".sefy";    // File extension for encrypted files
static bool FORCE_FLAG;                         // If true then overwrite files during encryption without asking user

/* Struct used for command line arguments */
typedef struct _options
{
  bool c;       /* -c flag: specify path to configuration file */
  char *configuration_file; /* path to configuration file */
  bool d;       /* -d flag: decrypt file */
  bool e;       /* -e flag: encrypt file */
  bool f;       /* -f flag: force overwrite if file exits */
  bool h;       /* -h flag: print usage information */
  bool i;       /* -i flag: generate and save a new key pair */ 
  bool o;       /* -o flag: specify output location of encrypted/decrypted file */
  char *output_file; /* path to output file */
  bool p;       /* -p flag: print Base64 encoded public key */
  bool s;       /* -s flag: overwritens and delete original file after encryption */
  bool optError; /* true if error during command line parsing */

} Options;

/* Struct used for storing the user's key pair */
typedef struct _config {
    unsigned char secretkey[crypto_box_SECRETKEYBYTES];
    unsigned char publickey[crypto_box_PUBLICKEYBYTES];
    char secretkey_b64[64];
    char publickey_b64[64];
} Config;

void 
error_exit(const char *message)
{
    fprintf(stderr, "Error: %s\n", message);
    exit(1);
}

char* 
b64_encode(char **b64_data, unsigned char * const data, size_t data_length)
{
    /*
     * Base64 encodes the content of DATA and saves the result to B64_DATA. 
     * It is upon the caller to free the allocated buffer B64_DATA with sodium_free().
     * Returns pointer to B64_DATA on success, and NULL if failed.
     */
    size_t b64_maxlen;

    b64_maxlen = sodium_base64_ENCODED_LEN(data_length, sodium_base64_VARIANT_ORIGINAL);
    *b64_data = (char*) sodium_malloc(b64_maxlen);
    if ( *b64_data == NULL )
        return NULL;

    memset(*b64_data, 0, b64_maxlen); 

    return sodium_bin2base64(*b64_data, b64_maxlen, data, data_length, sodium_base64_VARIANT_ORIGINAL);
}

int 
b64_decode(unsigned char **data, const char *b64_data, size_t b64_data_length)
{
    /*
     * Base64 decodes the content of B64_DATA and saves the result to DATA. 
     * It is upon the caller to free the allocated buffer DATA with sodium_free().
     * Returns 0 on success, and -1 if failed.
     */
    size_t data_length;
    data_length = (b64_data_length / 4) * 3;

    *data = (unsigned char*) sodium_malloc(data_length+1);
    if ( *data == NULL )
        return -1;
    memset(*data, 0, data_length);

    return sodium_base642bin(*data, data_length, b64_data, b64_data_length, NULL, &data_length, NULL, sodium_base64_VARIANT_ORIGINAL);
}

int 
is_ok_file(const char *file_path, int type)
{
    /*
     * Determines if FILE_PATH is ok to write to by evaluating file permissions 
     * and type of file.
     * If regular file or if file does not exist return 1, on fail return 0.
     */
    struct stat st;

    /* 
     * Get information about file and save it to ST buffer.
     * If file does not exist return with success.
     */
    if ( stat(file_path, &st) != 0 )
    {
        return 1;
    }

    /* Check if file is a "regular file" */
    if ( ( ! S_ISREG(st.st_mode) ) || S_ISLNK(st.st_mode) || S_ISCHR(st.st_mode) || S_ISDIR(st.st_mode) ||  S_ISFIFO(st.st_mode) || S_ISLNK(st.st_mode) )
    {
        return 0;
    }

    /* Check if process has correct permissions on FILE_PATH */
    if ( access(file_path, type) != 0 )
    {
        return 0;
    }

    return 1;
}

int 
overwrite_pass(int fd, char *buffer, size_t buffer_length, off_t file_size, size_t iteration)
{
    /*
     * Used by overwrite_file() to do the actual overwriting of a file's content.
     * Returns 0 on success, and 1 if failed.
     */
    long int offset = 0;
    long unsigned int remaining_bytes;
    unsigned char byte[] = {0xFF, 0x00};

    if ( lseek(fd, 0, SEEK_SET) == -1 )
    {
        return 1;
    }

    memset(buffer, byte[iteration], buffer_length);

    while ( 1 )
    {
        if ( write(fd, buffer, buffer_length) < 0 )
            return 1;
        offset += buffer_length;
        if ( lseek(fd, offset, SEEK_SET) == -1 )
            return 1;
        if ( (remaining_bytes = file_size - offset) < buffer_length )
            break;
    }

    if ( remaining_bytes > 0 )
    {
        if ( (buffer = realloc(buffer, remaining_bytes)) == NULL )
        {
            return 1;
        }
        memset(buffer, byte[iteration], remaining_bytes);
        if ( write(fd, buffer, remaining_bytes) < 0 )
        {
            return 1;
        }
    }

    return 0;
}

int 
overwrite_file(const char *filename)
{
    /*
     * Poor man's shred used to securly overwrite a file's content and
     * subsequently delete (unlink) the file.
     * Returns 0 on success, and 1 if failed.
     */
    struct stat st;
    size_t file_size;
    size_t buffer_length;
    char *buffer;
    int fd;

    if ( ! is_ok_file(filename, W_OK) )
        return 1;

    fd = open(filename, O_WRONLY | O_NOCTTY | 0);
    if ( fstat(fd, &st) != 0 )
    {
        close(fd);
        return 1;
    }

    if ( (file_size = st.st_size) == 0 )
    {
        close(fd);
        return 1;
    }

    buffer_length = (size_t) (st.st_size < st.st_blksize) ? st.st_size : st.st_blksize;
    buffer = malloc(buffer_length);
    for( size_t i = 0; i < 2; i++ )
    {
        if ( overwrite_pass(fd, buffer, buffer_length, st.st_size, i) != 0 )
        {
            free(buffer);
            return 1;
        }
        if ( fsync(fd) != 0 )
        {
            free(buffer);
            return 1;
        }
    }

    if ( unlink(filename) != 0 )
    {
        free(buffer);
        return 1;
    }

    free(buffer);
    close(fd);
  
    printf("The content of file %s has been overwritten and the file itself is now deleted.\n", filename);

    return 0;
}

size_t 
write_file(unsigned char *data, size_t data_length, const char *file_dst, const char *mode)
{
    /*
     * Write content of buffer DATA to FILE_DST.
     * Returns byte written on success, and 0 on failure.
     */
    FILE *fp;

    if ( ! is_ok_file(file_dst, W_OK) )
        return 0;

    if ( strlen(file_dst) > MAX_LEN_PATH - 1 )
        return 0;  
    if ( access(file_dst, F_OK) == 0 && FORCE_FLAG == false )
    {
        char yes_no[2];
        printf("This operation will overwrite file '%s'. Proceed [y/n]? ", file_dst);
        if ( fgets(yes_no, 2, stdin) == NULL )
            return 0;
        if ( strcmp(yes_no, "y") != 0 )
            return 0;
    }

    fp = fopen(file_dst, mode);
    if ( fp == NULL )
        return 0;

    if ( fwrite(data, sizeof(data[0]), data_length, fp) != data_length )
    {
        fclose(fp);
        return 0;
    }
    
    fclose(fp);

    return data_length; 
}

size_t 
read_file(unsigned char **data, const char *file_src)
{
    /*
     * Allocates memory and points data to it, then puts the file content there.
     * It is upon the caller to free the allocated buffer DATA with sodium_free().
     * Returns the file's size in bytes if successful, otherwise 0.
     */
    size_t file_size = 0;
    FILE *fp;
    
    if ( ! is_ok_file(file_src, R_OK) )
        return 0;

    fp = fopen(file_src, "rb");
    if ( fp == NULL )
        return 0;
    fseek(fp, 0L, SEEK_END);
    file_size = (size_t) ftell(fp);
    rewind(fp);

    /* 
     * Made up limit to save it from crashing a user's computer
     * because all of the file's content is loaded into RAM.
     * A better solution would be to read and perform operations
     * on chunks rather then a whole file..
     */
    if ( file_size > 1048576 )
    {
        fclose(fp);
        return 0;
    }

    *data = (unsigned char*) sodium_malloc(file_size);
    if ( *data == NULL )
    {
        fclose(fp);
        return 0;
    }
    memset(*data, 0, file_size);

    if ( fread(*data, sizeof(char), file_size, fp) != file_size )
    {
        fclose(fp);
        return 0;
    }
    
    fclose(fp);

    return file_size;
}

int 
config_file_load(Config *config, const char *config_file)
{
    /*
     * Loads a config file CONFIG_FILE and populates the CONFIG struct.
     * Will return 0 if successful, otherwise -1 if file does not exist or 1 for all other errors. 
     */
    int error = 0;
    char *config_key;
    char *config_value;
    size_t buffer_length = 256;
    const char delimiter[2] = " ";
    unsigned char *b64decoded_value = NULL;
    char *buffer = NULL;
    FILE *fp;
    
    if ( ! is_ok_file(config_file, R_OK) )
        return 1;

    fp = fopen(config_file, "r");
    if ( fp == NULL )
    {
        if ( errno == 2 )
            return -1;
        else
            return 1;
    }

    buffer = (char*) malloc(buffer_length * sizeof(char));
    while( 1 )
    {
        if ( fgets(buffer, buffer_length, fp) == NULL )
            break;
        config_key = strtok(buffer, delimiter);
        if ( config_key == NULL )
        {
            error++;
            break;
        }
        config_value = strtok(NULL, delimiter);
        if ( config_value == NULL )
        {
            error++;
            break;
        } 
        config_value[strcspn(config_value, "\n")] = '\0';
        if ( strncmp("secretkey", config_key, strlen("secretkey")) == 0 )
        {
            if ( b64_decode(&b64decoded_value, config_value, strlen(config_value)) != 0 )
            {
                error++;
                break;
            }
            memcpy(config->secretkey, b64decoded_value, crypto_box_SECRETKEYBYTES);
            sodium_free(b64decoded_value);
        }
        else if ( strncmp("publickey", config_key, strlen("publickey")) == 0 )
        {
            if ( b64_decode(&b64decoded_value, config_value, strlen(config_value)) != 0 )
            {
                error++;
                break;
            }
            memcpy(config->publickey, b64decoded_value, crypto_box_PUBLICKEYBYTES);
            memcpy(config->publickey_b64, config_value, 63);
            sodium_free(b64decoded_value);
        }
        else
        {
            error++;
            break;
        }
        
    }

    free(buffer);
    fclose(fp);

    if ( error > 0 )
        return 1;
    
    return 0;
}

void 
config_create_free(char *b64_secretkey, char *b64_publickey, char *data, FILE *fp)
{
    /*
     * Helper function for config_create() that free all the buffers, 
     * and close the file handle.
     */
    sodium_free(b64_secretkey);
    sodium_free(b64_publickey);
    sodium_free(data);
    if ( fp != NULL )
        fclose(fp);
}

int 
config_create(const char *file_dst)
{
    /*
     * Generates a new key pair and saves the
     * Base64 encoded value to FILE_DST.
     * Returns 0 on success, and 1 if failed.
     */
    unsigned char publickey[crypto_box_PUBLICKEYBYTES];    
    unsigned char secretkey[crypto_box_SECRETKEYBYTES];
    char *b64_publickey;
    char *b64_secretkey;
    size_t data_length;
    char *data = (char*) sodium_malloc(128);
    FILE *fp = NULL;

    if ( ! is_ok_file(file_dst, W_OK) )
        return 1;

    /* Generates the actual key pair */
    crypto_box_keypair(publickey, secretkey);

    b64_encode(&b64_secretkey, secretkey, crypto_box_SECRETKEYBYTES);
    b64_encode(&b64_publickey, publickey, crypto_box_PUBLICKEYBYTES);

    data_length = snprintf(data, 128, "secretkey %s\npublickey %s\n", b64_secretkey, b64_publickey);

    if (  data_length > 128 )
    {
        config_create_free(b64_secretkey, b64_publickey, data, fp);
        return 1;
    }

    if ( strlen(file_dst) > MAX_LEN_PATH - 1 )
    {
        config_create_free(b64_secretkey, b64_publickey, data, fp);
        return 1;
    }
    if ( access(file_dst, F_OK) == 0 )
    {
        char yes_no[2];
        printf("WARNING: This operation will overwrite (DELETE) the key(s) saved in '%s'.\n", file_dst);
        printf("It will not be possible to recover the key(s). Proceed [y/n]?  ");
        if ( fgets(yes_no, 2, stdin) == NULL )
            return 1;
        if ( strcmp(yes_no, "y") != 0 )
        {
            config_create_free(b64_secretkey, b64_publickey, data, fp);
            return 1;
        }
    }
    
    fp = fopen(file_dst, "w");
    if ( fp == NULL )
    {
        config_create_free(b64_secretkey, b64_publickey, data, fp);
        return 1;
    }

    if ( fwrite(data, sizeof(data[0]), data_length, fp) == data_length )
    {
        printf("A new key pair was generated and saved to the configuration file '%s'\n", file_dst);
        printf("It is advised to create a backup of the key pair and store it in a secure location.\n");

    }
    else
    {
        config_create_free(b64_secretkey, b64_publickey, data, fp);
        return 1;
    }

    config_create_free(b64_secretkey, b64_publickey, data, fp);

    if ( chmod(file_dst, S_IRUSR | S_IWUSR) != 0 )
        return 1;

    return 0;
}

void 
decrypt_file(const unsigned char *server_publickey, const unsigned char *server_secretkey, const char *file_src, const char *file_dst)
{
    /*
     * Decrypts the content of FILE_SRC with SERVER_SECRETKEY and saves the result 
     * to FILE_DST, or prints it to stdout if FILE_DST == "-".
     */
    size_t file_size;
    size_t ciphertext_length;
    unsigned char *ciphertext_from_file = NULL;
    
    if ( (file_size = read_file(&ciphertext_from_file, file_src)) == 0 )
    {
        error_exit("Failed to read file");
        if ( ciphertext_from_file != NULL )
            sodium_free(ciphertext_from_file);
    }

    ciphertext_length = (file_size - crypto_box_SEALBYTES);
    unsigned char decrypted[ciphertext_length];

    if ( crypto_box_seal_open(decrypted, ciphertext_from_file, file_size, server_publickey, server_secretkey) != 0 )
    {
        error_exit("Decryption failed");
        sodium_free(ciphertext_from_file);
    }

    sodium_free(ciphertext_from_file);

    if ( strncmp(file_dst, "-", strlen(file_dst)) == 0 )
    {
        for(size_t i = 0; i < (file_size - crypto_box_SEALBYTES); i++)
            printf("%c", decrypted[i]);
    }
    else    
    {
        if ( write_file(decrypted, ciphertext_length, file_dst, "wb") < ciphertext_length )
        {
            error_exit("Failed to write decrypted content to destination file");
        }
        else
            printf("Decrypted content saved to %s\n", file_src, file_dst);
    }
}

void 
encrypt_file(unsigned char *server_publickey, const char *file_src, char *flags_output_file)
{
    /*
     * Encrypts the content of FILE_SRC with SERVER_PUBLICKEY and saves the result
     * to FILE_DST.
     */
    size_t file_size;
    size_t ciphertext_length;
    char *filename_src_base = basename((char*)file_src);
    char *file_dst;
    unsigned char *data;

    if ( flags_output_file == NULL )
    {
        file_dst = (char*) malloc(strlen(filename_src_base) + strlen(FILENAME_EXTENSION) + 1);
        strcpy(file_dst, filename_src_base);
        strcat(file_dst, FILENAME_EXTENSION);
    }
    else
    {
        file_dst = (char*) malloc(strlen(flags_output_file) +1);
        strcpy(file_dst, flags_output_file);
    }

    if ( strlen(file_dst) > MAX_LEN_PATH - 1 )
    {
        free(file_dst);
        error_exit("Output filename/path too long");
    }
    if ( (file_size = read_file(&data, file_src)) == 0 )
    {
        if ( data != NULL )
            sodium_free(data);
        free(file_dst);
        error_exit("Failed to read file");
    }

    ciphertext_length = (crypto_box_SEALBYTES + file_size);
    unsigned char ciphertext[ciphertext_length];
    if ( crypto_box_seal(ciphertext, data, file_size, server_publickey) != 0 )
    {
        free(file_dst);
        sodium_free(data);
        error_exit("Encryption failed");
    }

    sodium_free(data);
    if ( strncmp(file_dst, "-", strlen(file_dst)) == 0 )
    {
        for(size_t i = 0; i < ciphertext_length; i++)
            printf("%c", ciphertext[i]);
    }
    else
    {
        if ( write_file(ciphertext, ciphertext_length, file_dst, "wb") < ciphertext_length )
        {
            free(file_dst);
            error_exit("Failed to write encrypted content to destination file");
        }
        printf("Encrypted content saved to %s\n", file_dst);
    }

    free(file_dst);
}

void
usage(bool error)
{
    if ( error )
    {
        fprintf(stderr, "Try '%s -h' for more information.\n", PROGRAM_NAME);
    }
    else
    {
        printf("Usage: %s [OPTIONS]... FILE...\n", PROGRAM_NAME);
        printf("Encrypt and decrypt specified file with XSalsa20 using Poly1305 for data integrity (MAC).\nThis utility utilize the Sodium library for its cryptographic operations.\n\n");
        printf(" -c\tpath to configuration file (if omitted '$HOME/.config/sefy' is used)\n");
        printf(" -d\tdecrypt (-o is required)\n");
        printf(" -e\tencrypt\n");
        printf(" -f\tforce overwrite if file specified with '-o' already exist\n");
        printf(" -h\tdisplay this help and exit\n");
        printf(" -i\tinitialize %s by generating a new key pair and write it to '$HOME/.config/%s',\n\tor the location specified with '-c'\n", PROGRAM_NAME, PROGRAM_NAME);
        printf(" -o\toutput filename (if omitted during encryption then original filename appended with %s is used);\n\tUse '-' to print result to stdout\n", FILENAME_EXTENSION);
        printf(" -p\tprint Base64 encoded public key\n");
        printf(" -s\tOverwrite and delete original file after encryption (A.K.A 'poor man's Shred')\n");
    }
}

int 
main(int argc, char *argv[])
{
    int c;
    char *file_name;
    int n_files;
    Config config;
    Options flags;
    char *config_file;

    memset(&flags, 0, sizeof(flags));

    /* Make sure sodium gets properly loaded */
    if ( sodium_init() < 0 ) 
        error_exit("Could not initialize libsodium");

    while ((c = getopt (argc, argv, "c:defhio:ps")) != -1)
    {
      switch (c)
        {
        case 'c':
            flags.c = true;
            flags.configuration_file = optarg;
            break;
        case 'd':
            if(flags.e)
                flags.optError = true;
            else
                flags.d = true;
            break;
        case 'e':
            if(flags.d == true)
                flags.optError = true;
            else
                flags.e = true;
            break;
        case 'f':
            FORCE_FLAG = true;
            break;
        case 'h':
            flags.h = true;
            usage(false);
            return 0;
            break;
        case 'i':
            flags.i = true;
            break;
        case 'o':
            flags.o = true;
            flags.output_file = optarg;
            break;
        case 'p':
            flags.p = true;
            break;
        case 's':
            flags.s = true;
            break;
        case '?':
            flags.optError = true;
            break;
        }
    }

    /* Return (exit) if user has supplied an invalid argument */
    if( flags.optError )
    {
        usage(flags.optError);
        return 1;
    }

    /* Set up path to configuration file */
    if ( flags.c && flags.configuration_file != NULL ) // If user specified configuration path
    {
        config_file = (char*) malloc(strlen(flags.configuration_file) + 1);
        strcpy(config_file, flags.configuration_file);
    }
    else // Default configuration path
    {
        const char *home;
        if ( (home = getenv("HOME")) == NULL )
            error_exit("Could not resolve $HOME environment variable");
        config_file = (char*) malloc(strlen(home) + strlen("/.config/") + strlen(PROGRAM_NAME) + 1);
        sprintf(config_file, "%s/.config/%s", home, PROGRAM_NAME);
    }

    /* Initialize client by creating key pair and saving to key file */
    if ( flags.i )
    {
        if ( config_create(config_file) != 0 )
        {
            free(config_file);
            error_exit("Failed to create keys and configuration file");
        }
        free(config_file);
        return 0;
    }

    /* Parse config file and populate struct config */
    int return_value = config_file_load(&config, config_file);
    free(config_file);
    if ( return_value == -1 )
    {
        fprintf(stderr, "Error: Configuration file not found\nSpecify path with '-c' or generate a new key pair with '-i'");
        return 1;
    }
    else if ( return_value == 1 )
        error_exit("Failed to read configuration file");

    /* Attempt to get user supplied file name */
    file_name = *(argv + optind);
    n_files = argc - optind;
    if ( n_files > 1 )
        error_exit("More than one file specified");

    /* Print public key */
    if ( flags.p )
    {
        printf("Public key: %s\n", config.publickey_b64);
        return 0;
    }

    /* 
     * All operations below requires that the user has supplied
     * a file to operate on.
     */

    /* Check that the user has supplied a filename */
    if ( n_files != 1 )
        error_exit("No file specified");

    /* Encrypt */
    if ( flags.e )
    {
        encrypt_file(config.publickey, file_name, flags.output_file);
        if ( flags.s )
        {
            if ( overwrite_file(file_name) != 0 )
                error_exit("Failed to overwrite and delete file");
        }
    }

    /* Decrypt */
    else if ( flags.d )
    {
        if ( ! flags.o )
            error_exit("Missing output file (-o)\n");
        decrypt_file(config.publickey, config.secretkey, file_name, flags.output_file);
    }

    return 0;
}