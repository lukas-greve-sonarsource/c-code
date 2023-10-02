#include <stdio.h>
#include <string.h>

void copyData(const char* input) {
    char buffer[10];
    strcpy(buffer, input); // Vulnerable line - no bounds checking on input size
    printf("Buffer contents: %s\n", buffer);
}

int main() {
    char userInput[20];
    printf("Enter your input: ");
    scanf("%s", userInput);
    copyData(userInput);
    return 0;
}

void copyData(const char* input) {
    char buffer[10];
    if (strncpy(buffer, input, sizeof(buffer) - 1) == NULL) {
        fprintf(stderr, "Error copying input to buffer\n");
        return;
    }
    buffer[sizeof(buffer) - 1] = '\0'; // Ensure null-terminated string
    printf("Buffer contents: %s\n", buffer);
}

int main() {
    char userInput[20];
    printf("Enter your input: ");
    if (scanf("%19s", userInput) != 1) {
        fprintf(stderr, "Error reading input from stdin\n");
        return 1;
    }
    copyData(userInput);
    return 0;
}

#include <stdio.h>
#include <string.h>

void vulnerable_function(char *input_string) {
    char buffer[10];
    strcpy(buffer, input_string); // potential out-of-bounds read vulnerability
    printf("%s\n", buffer);
}

int main() {
    char input[20] = "This is a test";
    vulnerable_function(input);
    return 0;
}

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define MAX_INPUT_LENGTH 100

void safer_function(const char *input_string) {
    char *buffer = (char *) malloc(MAX_INPUT_LENGTH + 1); // dynamically allocate buffer
    if (buffer == NULL) {
        printf("Error: Could not allocate memory for buffer.\n");
        exit(1);
    }
    strncpy(buffer, input_string, MAX_INPUT_LENGTH); // use strncpy to limit the number of characters copied
    buffer[MAX_INPUT_LENGTH] = '\0'; // add null terminator to the end of the string
    printf("%s\n", buffer);
    free(buffer); // free dynamically allocated memory
}

int main() {
    safer_function("Hello, world!");
    return 0;
}

#include <stdio.h>
#include <stdlib.h>

int main() {
  int arr[10];
  int index = 0;
  int input = 0;

  // read integers from user input and store them in the array
  while (scanf("%d", &input) == 1) {
    arr[index] = input;
    index++;
  }

  // process the array
  int sum = 0;
  for (int i = 0; i <= index; i++) {
    sum += arr[i];
  }

  printf("The sum of the numbers is: %d\n", sum);

  return 0;
}

#include <stdio.h>
#include <stdlib.h>

#define SIZE 10

int sum_array(const int arr[], size_t len);

int main(void) {
  int arr[SIZE] = {0};
  size_t i;

  for (i = 0; i < SIZE; i++) {
    arr[i] = i;
  }

  int sum = sum_array(arr, SIZE);
  printf("The sum of the array is: %d\n", sum);

  return 0;
}

int sum_array(const int arr[], size_t len) {
  size_t i;
  int sum = 0;

  for (i = 0; i < len; i++) {
    if (arr[i] > INT_MAX - sum) { // check for potential overflow
      printf("Integer overflow detected!\n");
      exit(EXIT_FAILURE);
    }
    sum += arr[i];
  }

  return sum;
}

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void display_user(char *username) {
    char sql_query[1000];
    sprintf(sql_query, "SELECT * FROM users WHERE username='%s'", username);
    // Execute the SQL query and display the result
}

int main() {
    char username[100];
    printf("Enter username: ");
    scanf("%s", username);
    display_user(username);
    return 0;
}

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main()
{
    char username[20];
    // Step 1: Receive user input
    printf("Enter username: ");
    scanf("%19s", username);

    // Step 2: Validate input
    for (int i = 0; i < strlen(username); i++) {
        if (!isalnum(username[i])) {
            printf("Invalid input.\n");
            exit(1);
        }
    }

    // Step 3: Use prepared statements to execute safe queries
    char query[100] = "SELECT * FROM users WHERE username = ?";
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db, query, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Failed to prepare statement: %s\n", sqlite3_errmsg(db));
        exit(1);
    }

    // Step 4: Bind parameters to the prepared statement
    rc = sqlite3_bind_text(stmt, 1, username, strlen(username), SQLITE_STATIC);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Failed to bind parameter: %s\n", sqlite3_errmsg(db));
        exit(1);
    }

    // Step 5: Execute the prepared statement
    rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        printf("Welcome %s!\n", sqlite3_column_text(stmt, 0));
    } else if (rc == SQLITE_DONE) {
        printf("User not found.\n");
    } else {
        fprintf(stderr, "Failed to execute statement: %s\n", sqlite3_errmsg(db));
        exit(1);
    }

    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return 0;
}

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void read_file(char* filename) {
  char path[100];
  snprintf(path, sizeof(path), "/home/user/data/%s", filename);
  FILE* file = fopen(path, "r");
  if (file) {
    printf("File contents:\n");
    char buffer[1024];
    while (fgets(buffer, sizeof(buffer), file)) {
      printf("%s", buffer);
    }
    fclose(file);
  } else {
    printf("File not found.\n");
  }
}

int main(int argc, char* argv[]) {
  if (argc < 2) {
    printf("Usage: %s filename\n", argv[0]);
    exit(1);
  }
  char* filename = argv[1];
  read_file(filename);
  return 0;
}

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// define a whitelist of allowed filenames
#define WHITELIST_SIZE 5
const char* whitelist[WHITELIST_SIZE] = {"data1.txt", "data2.csv", "data3.json", "data4.xml", "data5.html"};

// check if a filename is in the whitelist
int is_in_whitelist(char* filename) {
  for (int i = 0; i < WHITELIST_SIZE; i++) {
    if (strcmp(filename, whitelist[i]) == 0) {
      return 1; // filename matches one of the whitelist
    }
  }
  return 0; // filename does not match any of the whitelist
}

void read_file(char* filename) {
  char path[100];
  snprintf(path, sizeof(path), "/home/user/data/%s", filename);
  // check if the filename is in the whitelist
  if (!is_in_whitelist(filename)) {
    printf("Access denied.\n");
    return;
  }
  FILE* file = fopen(path, "r");
  if (file) {
    printf("File contents:\n");
    char buffer[1024];
    while (fgets(buffer, sizeof(buffer), file)) {
      printf("%s", buffer);
    }
    fclose(file);
  } else {
    printf("File not found.\n");
  }
}

int main(int argc, char* argv[]) {
  if (argc < 2) {
    printf("Usage: %s filename\n", argv[0]);
    exit(1);
  }
  char* filename = argv[1];
  read_file(filename);
  return 0;
}

#include <stdio.h>

int main() {
    // Vulnerable code: Incorrect default permissions
    FILE *file = fopen("sensitive_data.txt", "w"); // Create or overwrite the file
    if (file != NULL) {
        // Write some sensitive data to the file
        fprintf(file, "This is sensitive data that should not be accessible to all users.");
        fclose(file);
        printf("File created successfully.\n");
    } else {
        printf("Error: Unable to create the file.\n");
    }
    return 0;
}

#include <stdio.h>
#include <sys/stat.h>
#include <openssl/evp.h>

int main() {
    // Secure file path for storing sensitive_data.txt
    const char* file_path = "/path/to/sensitive_data.txt";
    
    // Secure code: Use mkstemp to create a temporary file with a random name and secure permissions (e.g., 0600)
    char tmp_path[] = "/tmp/sensitive_data_XXXXXX";
    int fd = mkstemp(tmp_path);
    if (fd == -1) {
        printf("Error: Unable to create a temporary file.\n");
        return 1;
    }
    
    // Secure code: Use fdopen to get a FILE pointer from the file descriptor
    FILE *file = fdopen(fd, "w");
    if (file == NULL) {
        printf("Error: Unable to open the temporary file.\n");
        close(fd);
        return 1;
    }
    
    // Write sensitive data to the file
    fprintf(file, "This is sensitive data that should not be accessible to all users.");
    
    // Close the file
    fclose(file);
    
    // Secure code: Use OpenSSL to encrypt the temporary file with AES-256-CBC and a secret key
    unsigned char key[] = "secretkey"; // This should be generated randomly and securely stored
    unsigned char iv[] = "initialvector"; // This should be generated randomly and securely stored
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        printf("Error: Unable to create a cipher context.\n");
        return 1;
    }
    
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
        printf("Error: Unable to initialize encryption.\n");
        EVP_CIPHER_CTX_free(ctx);
        return 1;
    }
    
    FILE *in = fopen(tmp_path, "rb");
    if (in == NULL) {
        printf("Error: Unable to open the temporary file for reading.\n");
        EVP_CIPHER_CTX_free(ctx);
        return 1;
    }
    
    FILE *out = fopen(file_path, "wb");
    if (out == NULL) {
        printf("Error: Unable to open the final file for writing.\n");
        EVP_CIPHER_CTX_free(ctx);
        fclose(in);
        return 1;
    }
    
    unsigned char inbuf[1024];
    unsigned char outbuf[1024 + EVP_MAX_BLOCK_LENGTH];
    int inlen, outlen;
    
    while ((inlen = fread(inbuf, 1, 1024, in)) > 0) {
        if (EVP_EncryptUpdate(ctx, outbuf, &outlen, inbuf, inlen) != 1) {
            printf("Error: Unable to encrypt data.\n");
            EVP_CIPHER_CTX_free(ctx);
            fclose(in);
            fclose(out);
            return 1;
        }
        
        fwrite(outbuf, 1, outlen, out);
    }
    
    if (EVP_EncryptFinal_ex(ctx, outbuf, &outlen) != 1) {
        printf("Error: Unable to finalize encryption.\n");
        EVP_CIPHER_CTX_free(ctx);
        fclose(in);
        fclose(out);
        return 1;
    }
    
    fwrite(outbuf, 1, outlen, out);
    
    // Free the cipher context and close the files
    EVP_CIPHER_CTX_free(ctx);
    fclose(in);
    fclose(out);
    
    // Delete the temporary file
    remove(tmp_path);
    
    printf("File created and secured successfully.\n");
    
    return 0;
}

#include <stdio.h>
#include <pthread.h>
#include <unistd.h> // For sleep

#define NUM_THREADS 2
#define ITERATIONS 1000000

int balance = 1000; // Initial balance

void *transferMoney(void *threadID) {
    long tid;
    tid = (long)threadID;

    for (int i = 0; i < ITERATIONS; i++) {
        int temp = balance; // Read the shared resource
        temp = temp - 100; // Modify the local copy (transfer 100 units)
        sleep(1); // Simulate some delay
        balance = temp; // Write back to the shared resource
    }

    pthread_exit(NULL);
}

int main() {
    pthread_t threads[NUM_THREADS];
    int rc;
    long t;

    for (t = 0; t < NUM_THREADS; t++) {
        rc = pthread_create(&threads[t], NULL, transferMoney, (void *)t);
        if (rc) {
            printf("Error: Unable to create thread %ld\n", t);
            return 1;
        }
    }

    for (t = 0; t < NUM_THREADS; t++) {
        pthread_join(threads[t], NULL);
    }

    printf("Final balance: %d\n", balance);

    return 0;
}

#include <stdio.h>
#include <pthread.h>
#include <unistd.h> // For sleep

#define NUM_THREADS 2
#define ITERATIONS 1000000

int balance = 1000; // Initial balance
pthread_mutex_t balance_mutex; // Mutex for protecting the balance variable

void *transferMoney(void *threadID) {
    long tid;
    tid = (long)threadID;

    for (int i = 0; i < ITERATIONS; i++) {
        if (pthread_mutex_lock(&balance_mutex) != 0) {
            // Handle error when locking the mutex
            perror("pthread_mutex_lock");
            return NULL;
        }
        int temp = balance; // Read the shared resource
        temp = temp - 100; // Modify the local copy (transfer 100 units)
        sleep(1); // Simulate some delay
        balance = temp; // Write back to the shared resource
        if (pthread_mutex_unlock(&balance_mutex) != 0) {
            // Handle error when unlocking the mutex
            perror("pthread_mutex_unlock");
            return NULL;
        }
    }

    pthread_exit(NULL);
}

int main() {
    pthread_t threads[NUM_THREADS];
    int rc;
    long t;

    // Initialize the mutex
    if (pthread_mutex_init(&balance_mutex, NULL) != 0) {
        printf("Error: Mutex initialization failed\n");
        return 1;
    }

    for (t = 0; t < NUM_THREADS; t++) {
        rc = pthread_create(&threads[t], NULL, transferMoney, (void *)t);
        if (rc) {
            printf("Error: Unable to create thread %ld\n", t);
            return 1;
        }
    }

    for (t = 0; t < NUM_THREADS; t++) {
        pthread_join(threads[t], NULL);
    }

    // Destroy the mutex
    pthread_mutex_destroy(&balance_mutex);

    printf("Final balance: %d\n", balance);

    return 0;
}

#include <stdlib.h>

int main() {
  int* ptr = (int*) malloc(sizeof(int)); // allocate memory
  *ptr = 42; // set the value of the memory

  free(ptr); // free the memory

  // use the pointer after the memory has been freed
  int result = *ptr; // This is a use after free vulnerability!

  return 0;
}

#include <stdlib.h>

int main() {
  int* ptr = NULL; // initialize the pointer to NULL
  ptr = (int*) malloc(sizeof(int)); // allocate memory
  if (ptr == NULL) {
    // handle error, such as by exiting the program
    return 1;
  }
  *ptr = 42; // set the value of the memory

  free(ptr); // free the memory
  ptr = NULL; // set the pointer to NULL

  // avoid using the pointer after it has been freed

  return 0;
}

#include <stdio.h>
#include <string.h>void vulnerable_function(char* input) {
  char buffer[100];
  strcpy(buffer, input);
  
  printf("Copying %d bytes to buffer...\n", strlen(input));
  
  if (strlen(input) > 50) {
    printf("Input too long!\n");
    return;
  }
  
  char command[100];
  sprintf(command, "echo %s", buffer);
  system(command);
  
  char* ptr = NULL;
  *ptr = 'a'; // dereferencing a NULL pointer
  
  int i;
  for (i = 0; i < strlen(buffer); i++) {
    buffer[i] += 10; // data corruption
  }
  
  printf("Modified buffer: %s\n", buffer);
}

int main(int argc, char* argv[]) {
  if (argc < 2) {
    printf("Usage: %s <input>\n", argv[0]);
    return 1;
  }
  
  printf("Running vulnerable function...\n");
  vulnerable_function(argv[1]);
  
  return 0;
}

#include <stdio.h>
#include <stdlib.h>
#include <string.h>void vulnerable_function(const char* input) {
    char buffer[100];
    size_t len = strnlen(input, sizeof(buffer)); // limit input length to size of buffer
    strncpy(buffer, input, len); // use strncpy to copy input to buffer

    printf("Copying %zu bytes to buffer...\n", len);

    if (len == sizeof(buffer)) { // check for input length equal to buffer size
        printf("Input too long!\n");
        return;
    }

    char command[200]; // increase size of command buffer
    snprintf(command, sizeof(command), "echo %s", buffer); // use snprintf to avoid buffer overflow
    system(command);

    int i;
    for (i = 0; i < len; i++) {
        if (buffer[i] < 127 - 10) { // prevent overflow and ensure printable characters
            buffer[i] += 10; // prevent data corruption by limiting loop to length of input
        }
    }

    printf("Modified buffer: %s\n", buffer);
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Usage: %s <input>\n", argv[0]);
        return 1;
    }

    printf("Running mitigated function...\n");
    vulnerable_function(argv[1]);

    return 0;
}

#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
    char filename[100];
    FILE *fp;
    if (argc != 2) {
        printf("Usage: %s <filename>\n", argv[0]);
        return 1;
    }
    strcpy(filename, argv[1]);
    fp = fopen(filename, "r");
    if (fp == NULL) {
        printf("Unable to open file: %s\n", filename);
        return 1;
    }
    // read and process file contents
    fclose(fp);
    return 0;
}

#include <stdio.h>
#include <string.h>
#include <ctype.h>

int main(int argc, char **argv) {
    char filename[100];
    FILE *fp;
    const char *allowed_filenames[] = { "file1.txt", "file2.txt", "file3.txt", NULL };
    int i;

    if (argc != 2) {
        printf("Usage: %s <filename>\n", argv[0]);
        return 1;
    }

    // validate filename against whitelist
    for (i = 0; allowed_filenames[i] != NULL; i++) {
        if (strcmp(argv[1], allowed_filenames[i]) == 0) {
            break;
        }
    }

    if (allowed_filenames[i] == NULL) {
        printf("Invalid filename: %s\n", argv[1]);
        return 1;
    }

    // validate filename against allowed characters
    for (i = 0; argv[1][i] != '\0'; i++) {
        if (!isalnum(argv[1][i]) && argv[1][i] != '.' && argv[1][i] != '_') {
            printf("Invalid character in filename: %c\n", argv[1][i]);
            return 1;
        }
    }

    fp = fopen(argv[1], "r");
    if (fp == NULL) {
        printf("Unable to open file: %s\n", argv[1]);
        return 1;
    }

    // read and process file contents
    fclose(fp);
    return 0;
}

#include <stdio.h>
#include <string.h>

void authenticate(char* username, char* password) {
    char validUsername[] = "admin";
    char validPassword[] = "password123";

    if (strcmp(username, validUsername) == 0 && strcmp(password, validPassword) == 0) {
        printf("Authentication successful.\n");
    } else {
        printf("Authentication failed.\n");
    }
}

int main() {
    char username[] = "admin";
    char password[] = "password123";

    authenticate(username, password);

    return 0;
}

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

// Simulating retrieval of credentials from a secure configuration file or external source
void retrieveCredentials(char* username, char* password) {
    // Retrieve the credentials from a secure storage location or external service
    // For demonstration purposes, assume retrieval logic from a secure source
    
    // Example: Retrieval from an encrypted configuration file using SSL/TLS
    SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
    if (ctx == NULL) {
        printf("Error: Unable to create SSL context.\n");
        exit(1);
    }

    // Load the trust store
    if (!SSL_CTX_load_verify_locations(ctx, "truststore.pem", NULL)) {
        printf("Error: Unable to load trust store.\n");
        exit(1);
    }

    // Create an SSL connection
    BIO* bio = BIO_new_ssl_connect(ctx);
    if (bio == NULL) {
        printf("Error: Unable to create SSL connection.\n");
        exit(1);
    }

    // Connect to the configuration file server
    BIO_set_conn_hostname(bio, "config.example.com:443");

    // Verify the server certificate
    SSL* ssl;
    BIO_get_ssl(bio, &ssl);
    if (SSL_get_verify_result(ssl) != X509_V_OK) {
        printf("Error: Server certificate verification failed.\n");
        exit(1);
    }

    // Read the encrypted credentials from the configuration file
    char encryptedCredentials[64];
    int len = BIO_read(bio, encryptedCredentials, sizeof(encryptedCredentials));
    if (len <= 0) {
        printf("Error: Unable to read encrypted credentials.\n");
        exit(1);
    }

    // Decrypt the credentials using a symmetric key
    // For demonstration purposes, assume decryption logic using a symmetric key
    // ...

    // Parse the decrypted credentials into username and password
    if (sscanf(decryptedCredentials, "%s %s", username, password) != 2) {
        printf("Error: Invalid credential format.\n");
        exit(1);
    }

    // Free the SSL resources
    BIO_free_all(bio);
    SSL_CTX_free(ctx);
}

// Compare two strings in constant time to prevent timing attacks
int constant_time_compare(const char* a, const char* b) {
    size_t len_a = strlen(a);
    size_t len_b = strlen(b);

    if (len_a != len_b) {
        return 0;
    }

    unsigned char result = 0;
    for (size_t i = 0; i < len_a; i++) {
        result |= a[i] ^ b[i];
    }
    
    return result == 0;
}

void authenticate(char* username, char* password) {
    // Perform authentication logic
    // For demonstration purposes, compare with retrieved credentials
    char retrievedUsername[32];
    char retrievedPassword[32];
    
     // Retrieve the hashed password using the username as a key
     retrieveCredentials(retrievedUsername, retrievedPassword);

     // Hash the input password using the same algorithm and salt as the retrieved password
     char hashedPassword[32];
     EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
     if (mdctx == NULL) {
         printf("Error: Unable to create hash context.\n");
         exit(1);
     }

     if (!EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL)) {
         printf("Error: Unable to initialize hash function.\n");
         exit(1);
     }

     // Assume a fixed salt for demonstration purposes
     unsigned char salt[] = "1234567890abcdef";

     if (!EVP_DigestUpdate(mdctx, salt, sizeof(salt))) {
         printf("Error: Unable to update hash with salt.\n");
         exit(1);
     }

     if (!EVP_DigestUpdate(mdctx, password, strlen(password))) {
         printf("Error: Unable to update hash with password.\n");
         exit(1);
     }

     unsigned int len;
     unsigned char digest[EVP_MAX_MD_SIZE];
     if (!EVP_DigestFinal_ex(mdctx, digest, &len)) {
         printf("Error: Unable to finalize hash.\n");
         exit(1);
     }

     EVP_MD_CTX_free(mdctx);

     // Convert the digest to a hex string
     for (unsigned int i = 0; i < len; i++) {
         sprintf(hashedPassword + (i * 2), "%02x", digest[i]);
     }
     
     hashedPassword[len * 2] = '\0';

     // Compare the input username and hashed password with the retrieved ones in constant time
     if (constant_time_compare(username, retrievedUsername) && constant_time_compare(hashedPassword, retrievedPassword)) {
         printf("Authentication successful.\n");
     } else {
         printf("Authentication failed.\n");
     }
}

int main() {
   char username[32];
   char password[32];

   retrieveCredentials(username, password);

   authenticate(username, password);

   // Clear credentials from memory
   memset(username, 0, sizeof(username));
   memset(password, 0, sizeof(password));

   return 0;
}

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void vulnerable_function(const char* input) {
    char buffer[100];
    size_t len = strnlen(input, sizeof(buffer)); // limit input length to size of buffer
    strncpy(buffer, input, len); // use strncpy to copy input to buffer

    printf("Copying %zu bytes to buffer...\n", len);

    if (len == sizeof(buffer)) { // check for input length equal to buffer size
        printf("Input too long!\n");
        return;
    }

    char command[200]; // increase size of command buffer
    snprintf(command, sizeof(command), "echo %s", buffer); // use snprintf to avoid buffer overflow
    system(command);

    int i;
    for (i = 0; i < len; i++) {
        if (buffer[i] < 127 - 10) { // prevent overflow and ensure printable characters
            buffer[i] += 10; // prevent data corruption by limiting loop to length of input
        }
    }

    printf("Modified buffer: %s\n", buffer);
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Usage: %s <input>\n", argv[0]);
        return 1;
    }

    printf("Running mitigated function...\n");
    vulnerable_function(argv[1]);

    return 0;
}
