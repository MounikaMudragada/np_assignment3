#include <iostream>
#include <string>
#include <regex>
#include <thread>
#include <atomic>
#include <csignal>
#include <cstdlib>
#include <vector>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

const size_t MAX_BUFFER_SIZE = 2048;    // Maximum buffer size for communication
const size_t NICKNAME_LIMIT = 12;       // Maximum allowed length for a nickname

using namespace std;

atomic<bool> isSessionActive(true);  // Indicates whether the client is active
int socketDescriptor = 0;            // Socket descriptor for server communication
string nickname;                     // Stores the user's nickname

// Gracefully handles SIGINT (Ctrl+C) signal to terminate the client
void signalHandler(int signalCode) {
    isSessionActive = false;
    close(socketDescriptor);
    cout << "\nExiting chat client. Goodbye!" << endl;
    exit(signalCode);
}

// Removes the "MSG <nickname>" prefix from a received message
string removeMessagePrefix(const string& message) {
    size_t firstSpace = message.find(' ');
    if (firstSpace == string::npos) return message;
    size_t secondSpace = message.find(' ', firstSpace + 1);
    if (secondSpace == string::npos) return message;

    if (message.substr(0, firstSpace) == "MSG") {
        return message.substr(secondSpace + 1);  // Return only the actual message content
    }
    return message;
}

// Splits a string into tokens using a specified delimiter, storing results in a vector
void tokenizeString(const string& text, const string& delimiter, vector<string>& tokens) {
    size_t start = 0;
    size_t end = text.find(delimiter);
    while (end != string::npos) {
        tokens.push_back(text.substr(start, end - start));
        start = end + delimiter.length();
        end = text.find(delimiter, start);
    }
    tokens.push_back(text.substr(start));
}

// Handles incoming messages from the server, including fragmented data
void receiveFromServer() {
    char recvBuffer[MAX_BUFFER_SIZE] = {};
    string messageBuffer;

    while (isSessionActive) {
        int bytesReceived = recv(socketDescriptor, recvBuffer, MAX_BUFFER_SIZE, 0);
        if (bytesReceived > 0) {
            messageBuffer += string(recvBuffer, bytesReceived);

            vector<string> messageQueue;
            tokenizeString(messageBuffer, "\n", messageQueue);

            // Handle incomplete message at the end
            if (!messageBuffer.empty() && messageBuffer.back() != '\n') {
                messageBuffer = messageQueue.back();  // Store incomplete message
                messageQueue.pop_back();
            } else {
                messageBuffer.clear();
            }

            for (const auto& message : messageQueue) {
                if (message.empty()) continue;

                string cleanedMessage = removeMessagePrefix(message);
                cout << cleanedMessage << endl;

                if (message == "QUIT") {
                    isSessionActive = false;
                    break;
                }
            }
        } else if (bytesReceived == 0) {
            cout << nickname << ": Server disconnected. Exiting chat..." << endl;
            isSessionActive = false;
        } else {
            cerr << "Error: Failed to read message from server." << endl;
            isSessionActive = false;
        }
        memset(recvBuffer, 0, MAX_BUFFER_SIZE);  // Clear buffer for reuse
    }
}

// Sends messages entered by the user to the server
void sendToServer() {
    string userMessage;
    while (isSessionActive) {
        cout.flush();
        getline(cin, userMessage);

        // Format the message with "MSG <nickname>" prefix
        string formattedMessage = "MSG " + nickname + " " + userMessage + "\n";
        if (send(socketDescriptor, formattedMessage.c_str(), formattedMessage.length(), 0) == -1) {
            cerr << "Error: Unable to send message to server." << endl;
            isSessionActive = false;
            break;
        }
    }
}

// Main function
int main(int argc, char* argv[]) {
    signal(SIGINT, signalHandler);  // Register SIGINT handler for graceful exit

    if (argc < 3) {
        cout << "Usage: " << argv[0] << " <server_ip:port> <nickname>" << endl;
        return 0;
    }

    string serverIP, serverPortStr;
    string serverInput = argv[1];
    size_t colonPosition = serverInput.find(':');
    if (colonPosition == string::npos) {
        cerr << "Error: Invalid format. Use <server_ip:port>." << endl;
        return 1;
    }
    serverIP = serverInput.substr(0, colonPosition);
    serverPortStr = serverInput.substr(colonPosition + 1);

    nickname = argv[2];
    if (nickname.length() > NICKNAME_LIMIT || !regex_match(nickname, regex("^[A-Za-z0-9_]+$"))) {
        cerr << "Error: Nickname must be at most " << NICKNAME_LIMIT << " characters and contain only letters, numbers, or underscores." << endl;
        return 1;
    }

    cout << "Connecting to " << serverIP << ":" << serverPortStr << " as '" << nickname << "'..." << endl;

    struct addrinfo hints{}, *serverInfo;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    int addrStatus = getaddrinfo(serverIP.c_str(), serverPortStr.c_str(), &hints, &serverInfo);
    if (addrStatus != 0) {
        cerr << "Error: Unable to resolve server address: " << gai_strerror(addrStatus) << endl;
        return 1;
    }

    socketDescriptor = socket(serverInfo->ai_family, serverInfo->ai_socktype, serverInfo->ai_protocol);
    if (socketDescriptor == -1) {
        cerr << "Error: Failed to create a socket." << endl;
        freeaddrinfo(serverInfo);
        return 1;
    }

    if (connect(socketDescriptor, serverInfo->ai_addr, serverInfo->ai_addrlen) == -1) {
        cerr << "Error: Unable to connect to the server." << endl;
        close(socketDescriptor);
        freeaddrinfo(serverInfo);
        return 1;
    }
    freeaddrinfo(serverInfo);

    char initialBuffer[MAX_BUFFER_SIZE] = {};
    int initialBytes = recv(socketDescriptor, initialBuffer, sizeof(initialBuffer), 0);
    if (initialBytes <= 0) {
        cerr << "Error: Failed to read server's initialization message." << endl;
        close(socketDescriptor);
        return 1;
    }
    cout << "Server says: " << string(initialBuffer, initialBytes);
    cout.flush();

    if (string(initialBuffer).find("HELLO 1") == string::npos) {
        cerr << "Error: Unsupported server protocol." << endl;
        close(socketDescriptor);
        return 1;
    }

    string nicknameMessage = "NICK " + nickname + "\n";
    if (send(socketDescriptor, nicknameMessage.c_str(), nicknameMessage.length(), 0) == -1) {
        cerr << "Error: Failed to send nickname to server." << endl;
        close(socketDescriptor);
        return 1;
    }

    char serverResponse[MAX_BUFFER_SIZE] = {};
    initialBytes = recv(socketDescriptor, serverResponse, sizeof(serverResponse), 0);
    if (initialBytes <= 0) {
        cerr << "Error: Failed to read server response." << endl;
        close(socketDescriptor);
        return 1;
    }

    string responseMessage(serverResponse, initialBytes);
    cout << "Server Response: " << responseMessage;

    if (responseMessage.find("OK") != string::npos) {
        cout << "Welcome to the chat!" << endl;
    }

    thread senderThread(sendToServer);
    receiveFromServer();

    senderThread.join();
    close(socketDescriptor);
    return 0;
}
