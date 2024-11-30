#include <cstdio>              // C Standard Input and Output Library for printf and fprintf
#include <string>              // C++ Standard Library for std::string
#include <cstring>             // C Standard Library for C-string functions like strlen, memset
#include <vector>              // C++ Standard Library for std::vector
#include <thread>              // C++ Standard Library for std::thread
#include <mutex>               // C++ Standard Library for std::mutex
#include <atomic>              // C++ Standard Library for std::atomic
#include <regex>               // C++ Standard Library for std::regex
#include <unistd.h>            // UNIX Standard Library for close, sleep
#include <netdb.h>             // Network Database Library for getaddrinfo
#include <arpa/inet.h>         // Definitions for internet operations
#include <sys/socket.h>        // Main sockets header
#include <netinet/in.h>        // Internet address family
#include <ifaddrs.h>           // Interface address structures
#include <signal.h>            // Signal handling
#include <cmath>               // C++ Standard Library for mathematical functions (may not be used)
#include <fcntl.h>             // File control options for non-blocking sockets

// Define constants for server configuration
#define MAX_CLIENTS 50                  // Maximum number of simultaneous clients
#define MAX_BUFFER_SIZE 2048            // Maximum size for the message buffer
#define MAX_NAME_LENGTH 12              // Maximum length for a client's nickname
#define PROTOCOL_MESSAGE "HELLO 1\n"    // Protocol version message sent to clients upon connection
#define OK_MESSAGE "OK\n"               // OK message sent to clients upon successful actions
#define ERROR_MESSAGE "ERROR\n"         // Error message sent to clients upon unsuccessful actions

// Use specific components from the std namespace
using std::string;
using std::vector;
using std::mutex;
using std::thread;
using std::regex;
using std::regex_match;

// Global variables
std::atomic<unsigned int> client_count(0);  // Atomic counter for the number of connected clients
int uid = 10;                               // Unique identifier for clients, starting from 10

// Client structure to hold client information
struct Client {
    struct sockaddr_in address;  // Client's socket address
    int sockfd;                  // Client's socket file descriptor
    int uid;                     // Client's unique identifier
    string name;                 // Client's chosen nickname
};

// Create a vector to hold pointers to clients, initialized to nullptr
vector<Client*> clients(MAX_CLIENTS, nullptr);
// Mutex to protect access to the clients vector
mutex clients_mutex;

// Function to handle errors and exit the program
void handle_error(const string& message) {
    perror(message.c_str());  // Print error message with details from errno
    exit(EXIT_FAILURE);       // Exit the program with a failure status
}

// Function to add a client to the clients vector
void add_client_to_queue(Client* client) {
    clients_mutex.lock();     // Lock the mutex to ensure exclusive access to clients vector
    for (auto& c : clients) {
        if (!c) {             // Find the first available slot (nullptr) in the clients vector
            c = client;       // Assign the client to the slot
            break;            // Exit the loop after adding the client
        }
    }
    clients_mutex.unlock();   // Unlock the mutex after modifying the clients vector
}

// Function to remove a client from the clients vector based on uid
void remove_client_from_queue(int uid) {
    clients_mutex.lock();     // Lock the mutex before modifying the clients vector
    for (auto& c : clients) {
        if (c && c->uid == uid) {  // Find the client with the matching uid
            c = nullptr;            // Set the slot to nullptr, effectively removing the client
            break;                  // Exit the loop after removal
        }
    }
    clients_mutex.unlock();   // Unlock the mutex after modification
}

// Function to send a message to all clients except the sender
void send_message_to_all(const string& message, int sender_uid) {
    clients_mutex.lock();     // Lock the mutex before accessing the clients vector
    for (auto& c : clients) {
        if (c && c->uid != sender_uid) {  // Check if the client is not the sender
            if (send(c->sockfd, message.c_str(), message.length(), 0) <= 0) {
                // If sending the message fails
                printf("error: failed to send message to client (uid=%d)\n", c->uid);
                fflush(stdout);  // Flush stdout to ensure immediate output
                break;           // Exit the loop on failure
            }
        }
    }
    clients_mutex.unlock();   // Unlock the mutex after sending messages
}

// Function to handle communication with a client
void handle_client(Client* client) {
    char buffer[MAX_BUFFER_SIZE];  // Buffer to store messages received from the client
    bool leave_flag = false;       // Flag to determine if the client wants to leave

    client_count++;  // Increment the global client count

    while (true) {
        if (leave_flag) break;  // Exit the loop if the client has left

        int receive = recv(client->sockfd, buffer, MAX_BUFFER_SIZE, 0);  // Receive data from the client
        if (receive > 0) {
            buffer[receive] = '\0';  // Null-terminate the received data
            if (strlen(buffer) > 0) {
                // Convert the buffer to a string for easier manipulation
                string buffer_str(buffer);

                // Check if the message starts with "MSG "
                if (buffer_str.rfind("MSG ", 0) == 0) {
                    // Extract the message content after "MSG "
                    string message = buffer_str.substr(4);
                    // Remove any trailing whitespace characters
                    message.erase(message.find_last_not_of(" \n\r\t") + 1);

                    // Check if the message length is within the limit
                    if (message.length() <= 255) {
                        // Format the message to include the sender's name
                        string formatted_message = "MSG " + client->name + " " + message + "\n";
                        // Print the message to the server console
                        printf("%s: %s\n", client->name.c_str(), message.c_str());
                        fflush(stdout);  // Flush stdout to ensure immediate output
                        // Send the message to all other clients
                        send_message_to_all(formatted_message, client->uid);
                    } else {
                        // If the message is too long, send an error message
                        string error_message = "ERROR " + client->name + ": message too long\n";
                        send_message_to_all(error_message, client->uid);
                    }
                } else {
                    // If the message format is invalid, send an error message to the client
                    string error_message = "ERROR invalid message format\n";
                    send(client->sockfd, error_message.c_str(), error_message.length(), 0);
                }
            }
        } else if (receive == 0) {
            // If receive returns 0, the client has disconnected
            printf("%s left the chat\n", client->name.c_str());
            fflush(stdout);  // Flush stdout to ensure immediate output
            // Notify other clients that this client has left
            string leave_message = "MSG " + client->name + " has left the chat\n";
            send_message_to_all(leave_message, client->uid);
            leave_flag = true;  // Set the flag to exit the loop
        } else {
            // If receive returns -1, there was an error
            printf("error: client (uid=%d) communication error\n", client->uid);
            fflush(stdout);  // Flush stdout to ensure immediate output
            leave_flag = true;  // Set the flag to exit the loop
        }
        memset(buffer, 0, MAX_BUFFER_SIZE);  // Clear the buffer for the next message
    }

    // Clean up after the client disconnects
    close(client->sockfd);                  // Close the client's socket
    remove_client_from_queue(client->uid);  // Remove the client from the clients vector
    delete client;                          // Delete the client object to free memory
    client_count--;                         // Decrement the global client count
}

// Function to initialize the server socket with retries
int initialize_server_socket(const char* host, const char* port) {
    struct addrinfo hints{}, *res;        // Structures for address information
    memset(&hints, 0, sizeof(hints));     // Zero out the hints structure
    hints.ai_family = AF_UNSPEC;          // Allow IPv4 or IPv6
    hints.ai_socktype = SOCK_STREAM;      // Use TCP sockets
    hints.ai_flags = AI_PASSIVE;          // For wildcard IP address

    int sockfd;                           // Socket file descriptor
    int retry_count = 5;                  // Number of retries for initialization

    while (retry_count--) {
        // Get address information for the host and port
        if (getaddrinfo(host, port, &hints, &res) != 0) {
            fprintf(stderr, "error: failed to resolve socket address. retrying...\n");
            fflush(stderr);               // Flush stderr to ensure immediate output
            sleep(1);                     // Wait for 1 second before retrying
            continue;
        }

        // Create a socket
        sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
        if (sockfd < 0) {
            fprintf(stderr, "error: server socket creation failed. retrying...\n");
            fflush(stderr);
            freeaddrinfo(res);            // Free the address information
            sleep(1);                     // Wait before retrying
            continue;
        }

        // Set socket options to allow reuse of address and port
        int option = 1;
        if (setsockopt(sockfd, SOL_SOCKET, (SO_REUSEPORT | SO_REUSEADDR),
                       reinterpret_cast<char*>(&option), sizeof(option)) < 0) {
            fprintf(stderr, "error: setsockopt failed. retrying...\n");
            fflush(stderr);
            close(sockfd);                // Close the socket
            freeaddrinfo(res);            // Free the address information
            sleep(1);                     // Wait before retrying
            continue;
        }

        // Bind the socket to the specified host and port
        if (bind(sockfd, res->ai_addr, res->ai_addrlen) < 0) {
            fprintf(stderr, "error: server socket bind failed. retrying...\n");
            fflush(stderr);
            close(sockfd);                // Close the socket
            freeaddrinfo(res);            // Free the address information
            sleep(1);                     // Wait before retrying
            continue;
        }

        // Successfully initialized the server socket
        freeaddrinfo(res);                // Free the address information
        return sockfd;                    // Return the socket file descriptor
    }

    // If all retries fail, handle the error and exit
    handle_error("fatal error: server socket initialization failed after retries");
    return -1;  // This line will never be reached due to exit in handle_error
}

// Signal handler for graceful shutdown of the server
void signal_handler(int sig) {
    printf("\nshutting down server gracefully...\n");
    fflush(stdout);  // Flush stdout to ensure immediate output
    exit(EXIT_SUCCESS);  // Exit the program with success status
}

// Main function to start the server
int main(int argc, char** argv) {
    // Check if the correct number of command-line arguments is provided
    if (argc != 2) {
        fprintf(stderr, "error: usage: %s <host:port>\n", argv[0]);
        fflush(stderr);
        return EXIT_FAILURE;  // Exit with failure status due to incorrect usage
    }

    // Parse the host and port from the command-line argument
    char* host = strtok(argv[1], ":");     // Extract the host part before ':'
    char* port = strtok(nullptr, ":");     // Extract the port part after ':'
    if (!host || !port) {
        // If either host or port is missing, display an error
        fprintf(stderr, "error: invalid host or port format. use <host:port>\n");
        fflush(stderr);
        return EXIT_FAILURE;  // Exit with failure status
    }
    printf("host: %s, port: %s\n", host, port);
    fflush(stdout);  // Flush stdout to ensure immediate output

    // Register the signal handler for SIGINT (Ctrl+C)
    signal(SIGINT, signal_handler);

    // Initialize the server socket
    int server_sockfd = initialize_server_socket(host, port);

    // Set the server socket to non-blocking mode
    fcntl(server_sockfd, F_SETFL, O_NONBLOCK);

    // Start listening for incoming connections
    if (listen(server_sockfd, MAX_CLIENTS) < 0) {
        // If listening fails, handle the error and exit
        handle_error("error: server listen failed");
    }
    printf("server listening on %s:%s...\n", host, port);
    fflush(stdout);  // Flush stdout to ensure immediate output

    // Main loop to accept and handle incoming client connections
    while (true) {
        struct sockaddr_in client_addr;  // Structure to hold client address information
        socklen_t client_len = sizeof(client_addr);

        // Accept a new client connection
        int client_sockfd =
            accept(server_sockfd, (struct sockaddr*)&client_addr, &client_len);

        if (client_sockfd < 0) {
            // If no client is trying to connect, continue the loop (non-blocking)
            continue;
        }

        // Check if the maximum number of clients has been reached
        if ((client_count + 1) == MAX_CLIENTS) {
            fprintf(stderr, "error: maximum clients reached. rejected: %d\n", ntohs(client_addr.sin_port));
            fflush(stderr);
            close(client_sockfd);  // Close the client's socket
            continue;
        }

        // Send the protocol version message to the client
        if (send(client_sockfd, PROTOCOL_MESSAGE, strlen(PROTOCOL_MESSAGE), 0) <= 0) {
            fprintf(stderr, "error: failed to send protocol message\n");
            fflush(stderr);
            close(client_sockfd);  // Close the client's socket
            continue;
        }

        // Buffer to store the client's nickname message
        char nick_buffer[MAX_BUFFER_SIZE] = {0};
        int nick_bytes = recv(client_sockfd, nick_buffer, sizeof(nick_buffer), 0);

        if (nick_bytes <= 0) {
            // If receiving the nickname fails, display an error and close the socket
            fprintf(stderr, "error: receiving NICK message failed\n");
            fflush(stderr);
            close(client_sockfd);
            continue;
        }
        nick_buffer[nick_bytes] = '\0';  // Null-terminate the received data

        // Extract the client's nickname from the message
        char client_name[MAX_NAME_LENGTH + 1];  // Buffer to store the nickname
        sscanf(nick_buffer, "NICK %s", client_name);
        client_name[strcspn(client_name, "\n")] = '\0';  // Remove any newline character

        // Define a regular expression for valid nicknames (alphanumeric and underscores)
        regex nickname_regex("^[A-Za-z0-9_]+$");

        // Validate the client's nickname
        if (regex_match(client_name, nickname_regex) &&
            strlen(client_name) <= MAX_NAME_LENGTH) {
            // If the nickname is valid, send an OK message
            if (send(client_sockfd, OK_MESSAGE, strlen(OK_MESSAGE), 0) <= 0) {
                fprintf(stderr, "error: sending OK message failed\n");
                fflush(stderr);
                close(client_sockfd);
                continue;
            }

            // Create a new client object and populate its fields
            auto* client = new Client;
            client->address = client_addr;
            client->sockfd = client_sockfd;
            client->uid = uid++;
            client->name = client_name;

            // Notify that the client has joined the chat
            printf("%s joined the chat\n", client->name.c_str());
            fflush(stdout);

            // Add the client to the clients vector and start a thread to handle communication
            add_client_to_queue(client);
            thread(handle_client, client).detach();

        } else {
            // If the nickname is invalid, send an error message and close the socket
            send(client_sockfd, ERROR_MESSAGE, strlen(ERROR_MESSAGE), 0);
            close(client_sockfd);
        }
    }

    // Close the server socket (this line is never reached due to infinite loop)
    close(server_sockfd);
    return 0;  // Return 0 to indicate successful execution
}
