/*
 * SmartBank Secure Banking System v2.2
 * File-based persistent storage, salted password hashing, encrypted DB.
 * C++11, single file, no external libraries.
 */

#include <iostream>
#include <string>
#include <vector>
#include <stdexcept>
#include <fstream>
#include <sstream>
#include <cstdlib>
#include <ctime>
#include <iomanip>
#include <limits>
#include <algorithm>
#include <cstdint>
#include <random>

#ifdef _WIN32
#include <windows.h>
#endif

using namespace std;

const string FILE_ACCOUNTS     = "db_accounts.dat";
const string FILE_CARDS        = "db_cards.dat";
const string FILE_USERS        = "db_users.dat";
const string FILE_APPLICATIONS = "db_applications.dat";
const string FILE_TRANSACTIONS = "transaction_history.txt";
const string FILE_AUDIT        = "audit_log.txt";
const string FILE_ADMIN_CONFIG = "admin_config.dat";

// One pending registration, waiting for admin approval.
// Password is stored already-hashed + its salt, never in plain text.
struct AccountApplication {
    string fullName;
    string username;
    string passwordHash;
    string salt;
    string nidNumber;
    string faceVerificationStatus;
};

vector<AccountApplication> pendingApplications;

class SecuritySystem {
private:
    static const char XOR_KEY = 'K';

    static uint32_t rightRotate(uint32_t value, unsigned int count) {
        return (value >> count) | (value << (32 - count));
    }

public:
    static string getCurrentTimestamp() {
        time_t now = time(0);
        char buf[20];
        strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", localtime(&now));
        return string(buf);
    }

    static void logEvent(const string& eventMessage) {
        ofstream logFile(FILE_AUDIT, ios::app);
        if (logFile.is_open()) {
            logFile << "[" << getCurrentTimestamp() << "] [LOG] " << eventMessage << "\n";
        }
    }

    // Single-byte XOR cipher, used for lightweight obfuscation of data files.
    // NOTE: this is not real encryption, just keeps files unreadable in a text editor.
    static string encryptDecrypt(const string& data) {
        string output = data;
        for (size_t i = 0; i < data.size(); i++) {
            output[i] = data[i] ^ XOR_KEY;
        }
        return output;
    }

    // Random hex salt, unique per user/admin credential.
    static string generateSalt() {
        static mt19937_64 rng(random_device{}());
        uint64_t value = rng();
        ostringstream oss;
        oss << hex << setw(16) << setfill('0') << value;
        return oss.str();
    }

    // Hand-written SHA-256 (FIPS 180-4). Returns a 64-char hex digest.
    static string sha256(const string& input) {
        static const uint32_t k[64] = {
            0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
            0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
            0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
            0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
            0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
            0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
            0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
            0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
        };

        uint32_t h[8] = {
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
            0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
        };

        vector<uint8_t> msg(input.begin(), input.end());
        uint64_t bitLen = (uint64_t)msg.size() * 8;
        msg.push_back(0x80);
        while (msg.size() % 64 != 56) msg.push_back(0x00);
        for (int i = 7; i >= 0; i--) msg.push_back((uint8_t)(bitLen >> (i * 8)));

        for (size_t chunkStart = 0; chunkStart < msg.size(); chunkStart += 64) {
            uint32_t w[64];
            for (int i = 0; i < 16; i++) {
                w[i] = ((uint32_t)msg[chunkStart + i * 4]     << 24) |
                       ((uint32_t)msg[chunkStart + i * 4 + 1] << 16) |
                       ((uint32_t)msg[chunkStart + i * 4 + 2] << 8)  |
                       ((uint32_t)msg[chunkStart + i * 4 + 3]);
            }
            for (int i = 16; i < 64; i++) {
                uint32_t s0 = rightRotate(w[i - 15], 7) ^ rightRotate(w[i - 15], 18) ^ (w[i - 15] >> 3);
                uint32_t s1 = rightRotate(w[i - 2], 17) ^ rightRotate(w[i - 2], 19) ^ (w[i - 2] >> 10);
                w[i] = w[i - 16] + s0 + w[i - 7] + s1;
            }

            uint32_t a = h[0], b = h[1], c = h[2], d = h[3];
            uint32_t e = h[4], f = h[5], g = h[6], hh = h[7];

            for (int i = 0; i < 64; i++) {
                uint32_t S1    = rightRotate(e, 6) ^ rightRotate(e, 11) ^ rightRotate(e, 25);
                uint32_t ch    = (e & f) ^ ((~e) & g);
                uint32_t temp1 = hh + S1 + ch + k[i] + w[i];
                uint32_t S0    = rightRotate(a, 2) ^ rightRotate(a, 13) ^ rightRotate(a, 22);
                uint32_t maj   = (a & b) ^ (a & c) ^ (b & c);
                uint32_t temp2 = S0 + maj;

                hh = g; g = f; f = e; e = d + temp1;
                d = c; c = b; b = a; a = temp1 + temp2;
            }

            h[0] += a; h[1] += b; h[2] += c; h[3] += d;
            h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
        }

        ostringstream result;
        for (int i = 0; i < 8; i++) {
            result << hex << setfill('0') << setw(8) << h[i];
        }
        return result.str();
    }

    // Salted hash: sha256(salt + password). Defeats plain rainbow-table lookups.
    static string hashPassword(const string& password, const string& salt) {
        return sha256(salt + password);
    }

    static void saveTransactionToFile(int accNo, const string& type, double amount, double currentBalance) {
        ofstream file(FILE_TRANSACTIONS, ios::app);
        if (file.is_open()) {
            string record = "[" + getCurrentTimestamp() + "] Acc: " + to_string(accNo)
                          + " | Type: " + type
                          + " | Amt: " + to_string(amount)
                          + " | Bal: " + to_string(currentBalance);
            file << encryptDecrypt(record) << "\n";
        }
    }

    static void viewAllTransactions() {
        ifstream file(FILE_TRANSACTIONS);
        if (!file.is_open()) {
            cout << "  No transaction history file found or it is empty.\n";
            return;
        }
        cout << "\n--- Decrypted Master Transaction History (Admin View) ---\n";
        string line;
        int count = 0;
        while (getline(file, line)) {
            cout << "  " << encryptDecrypt(line) << "\n";
            count++;
        }
        cout << "---------------------------------------------------------\n";
        cout << "  Total Records: " << count << "\n";
    }

    // OTP generator. Random engine is seeded once in main(), not here,
    // otherwise two OTPs requested in the same second would be identical.
    static bool verifyOTP() {
        int generatedOTP = rand() % 9000 + 1000;
        cout << "\n  [SMS Gateway Simulated]: Your SmartBank 2FA OTP is: " << generatedOTP << "\n";

        int inputOTP;
        cout << "  Enter the OTP sent to your phone: ";
        cin >> inputOTP;

        if (inputOTP == generatedOTP) {
            cout << "  OTP verification successful.\n";
            logEvent("OTP verification passed.");
            return true;
        }
        logEvent("ALERT: Failed OTP verification attempt.");
        cout << "  Invalid OTP code entered!\n";
        return false;
    }

    static vector<string> readEncryptedFile(const string& filename) {
        vector<string> lines;
        ifstream fin(filename, ios::binary);
        if (!fin.is_open()) return lines;
        string line;
        while (getline(fin, line)) {
            if (!line.empty())
                lines.push_back(encryptDecrypt(line));
        }
        return lines;
    }

    static void writeEncryptedFile(const string& filename, const vector<string>& lines) {
        ofstream fout(filename, ios::binary);
        for (const string& l : lines)
            fout << encryptDecrypt(l) << "\n";
    }

    static void saveAccount(int accNo, double balance, const string& accType) {
        vector<string> lines = readEncryptedFile(FILE_ACCOUNTS);
        string newLine = to_string(accNo) + " " + to_string(balance) + " " + accType;
        bool found = false;
        for (size_t i = 0; i < lines.size(); i++) {
            istringstream ss(lines[i]);
            int no; double bal; string type;
            ss >> no >> bal >> type;
            if (no == accNo) { lines[i] = newLine; found = true; }
        }
        if (!found) lines.push_back(newLine);
        writeEncryptedFile(FILE_ACCOUNTS, lines);
    }

    static void saveCard(const string& cardNo, const string& pin, bool isBlocked, int attempts) {
        vector<string> lines = readEncryptedFile(FILE_CARDS);
        string newLine = cardNo + " " + pin + " " + to_string(isBlocked ? 1 : 0) + " " + to_string(attempts);
        bool found = false;
        for (size_t i = 0; i < lines.size(); i++) {
            istringstream ss(lines[i]);
            string cno, cp; int bl, at;
            ss >> cno >> cp >> bl >> at;
            if (cno == cardNo) { lines[i] = newLine; found = true; }
        }
        if (!found) lines.push_back(newLine);
        writeEncryptedFile(FILE_CARDS, lines);
    }

    // Stores username, salted hash, salt, lock state, linked account/card.
    static void saveUser(const string& username, const string& passwordHash, const string& salt,
                          bool isLocked, int loginAttempts,
                          int accNo, const string& cardNo) {
        vector<string> lines = readEncryptedFile(FILE_USERS);
        string newLine = username + " " + passwordHash + " " + salt + " " +
                         to_string(isLocked ? 1 : 0) + " " +
                         to_string(loginAttempts) + " " +
                         to_string(accNo) + " " + cardNo;
        bool found = false;
        for (size_t i = 0; i < lines.size(); i++) {
            istringstream ss(lines[i]);
            string u, p, s, cn; int lk, la, an;
            ss >> u >> p >> s >> lk >> la >> an >> cn;
            if (u == username) { lines[i] = newLine; found = true; }
        }
        if (!found) lines.push_back(newLine);
        writeEncryptedFile(FILE_USERS, lines);
    }

    static void saveAllApplications(const vector<AccountApplication>& apps) {
        vector<string> lines;
        for (const AccountApplication& app : apps) {
            lines.push_back(app.fullName + "|" + app.username + "|" +
                            app.passwordHash + "|" + app.salt + "|" +
                            app.nidNumber + "|" + app.faceVerificationStatus);
        }
        writeEncryptedFile(FILE_APPLICATIONS, lines);
    }

    static void loadApplications(vector<AccountApplication>& apps) {
        apps.clear();
        vector<string> lines = readEncryptedFile(FILE_APPLICATIONS);
        for (const string& line : lines) {
            if (line.empty()) continue;
            istringstream ss(line);
            AccountApplication app;
            getline(ss, app.fullName,               '|');
            getline(ss, app.username,               '|');
            getline(ss, app.passwordHash,           '|');
            getline(ss, app.salt,                   '|');
            getline(ss, app.nidNumber,              '|');
            getline(ss, app.faceVerificationStatus, '|');
            apps.push_back(app);
        }
    }

    static bool loadCardData(const string& cardNo, string& pin, bool& isBlocked, int& attempts) {
        vector<string> lines = readEncryptedFile(FILE_CARDS);
        for (const string& line : lines) {
            istringstream ss(line);
            string cno, cp; int bl, at;
            ss >> cno >> cp >> bl >> at;
            if (cno == cardNo) {
                pin = cp; isBlocked = (bl == 1); attempts = at;
                return true;
            }
        }
        return false;
    }
};

// Handles the admin master password separately from the source code.
// On first run it asks the operator to set one and stores a salted hash.
// The plain password is never written to disk or hard-coded anywhere.
class AdminAuth {
public:
    static void ensureAdminPasswordExists() {
        ifstream check(FILE_ADMIN_CONFIG);
        if (check.good()) return;

        string pass1, pass2;
        cout << "\n  [First-Time Setup] No admin password found.\n";
        do {
            cout << "  Set a new Admin Master Password: ";
            cin >> pass1;
            cout << "  Confirm Admin Master Password : ";
            cin >> pass2;
            if (pass1 != pass2) cout << "  Passwords did not match, try again.\n";
        } while (pass1 != pass2 || pass1.empty());

        string salt = SecuritySystem::generateSalt();
        string hash = SecuritySystem::hashPassword(pass1, salt);

        vector<string> line = { salt + " " + hash };
        SecuritySystem::writeEncryptedFile(FILE_ADMIN_CONFIG, line);
        SecuritySystem::logEvent("Admin master password configured.");
        cout << "  Admin password saved securely.\n";
    }

    static bool verify(const string& inputPass) {
        vector<string> lines = SecuritySystem::readEncryptedFile(FILE_ADMIN_CONFIG);
        if (lines.empty()) return false;
        istringstream ss(lines[0]);
        string salt, hash;
        ss >> salt >> hash;
        return SecuritySystem::hashPassword(inputPass, salt) == hash;
    }
};

class Account {
private:
    int    accountNumber;
    double balance;
    string accountType;

public:
    Account(int accNo, double initialBalance, const string& type) {
        if (initialBalance < 0) throw invalid_argument("Initial deposit cannot be negative!");
        accountNumber = accNo;
        balance       = initialBalance;
        accountType   = type;
        SecuritySystem::saveAccount(accountNumber, balance, accountType);
        SecuritySystem::saveTransactionToFile(accountNumber, "Initial_Deposit", initialBalance, balance);
    }

    // Used when rebuilding accounts from the database file (doesn't re-save).
    Account(int accNo, double loadedBalance, const string& type, bool fromFile) {
        accountNumber = accNo;
        balance       = loadedBalance;
        accountType   = type;
        (void)fromFile;
    }

    int    getAccountNumber() const { return accountNumber; }
    double getBalance()       const { return balance; }
    string getAccountType()   const { return accountType; }

    void deposit(double amount) {
        if (amount <= 0) throw invalid_argument("Deposit amount must be positive!");
        balance += amount;
        SecuritySystem::saveAccount(accountNumber, balance, accountType);
        SecuritySystem::saveTransactionToFile(accountNumber, "Deposit", amount, balance);
        cout << "  Successfully deposited: " << fixed << setprecision(2) << amount << " BDT\n";
        displayBalance();
    }

    void withdraw(double amount) {
        if (amount <= 0) throw invalid_argument("Withdrawal amount must be positive!");
        if (amount > balance) throw runtime_error("Insufficient balance!");
        balance -= amount;
        SecuritySystem::saveAccount(accountNumber, balance, accountType);
        SecuritySystem::saveTransactionToFile(accountNumber, "Withdraw", amount, balance);
        cout << "  Withdrawal successful: " << fixed << setprecision(2) << amount << " BDT\n";
        displayBalance();
    }

    void transfer(Account& destination, double amount) {
        if (amount <= 0) throw invalid_argument("Transfer amount must be positive!");
        if (amount > balance) throw runtime_error("Insufficient balance for transfer!");
        balance -= amount;
        SecuritySystem::saveAccount(accountNumber, balance, accountType);
        destination.deposit(amount);
        SecuritySystem::saveTransactionToFile(accountNumber,
            "Transfer_To_" + to_string(destination.getAccountNumber()), amount, balance);
    }

    void displayBalance() const {
        cout << "  >>> [Current Balance: " << fixed << setprecision(2) << balance << " BDT] <<<\n";
    }
};

class Card {
private:
    string cardNumber;
    string pin;
    int    pinAttempts;
    bool   isBlocked;

public:
    Card(const string& cardNo, const string& cardPin) {
        cardNumber  = cardNo;
        pin         = cardPin;
        pinAttempts = 0;
        isBlocked   = false;
        SecuritySystem::saveCard(cardNumber, pin, isBlocked, pinAttempts);
    }

    Card(const string& cardNo, const string& cardPin, bool blocked, int attempts) {
        cardNumber  = cardNo;
        pin         = cardPin;
        isBlocked   = blocked;
        pinAttempts = attempts;
    }

    string getCardNumber()  const { return cardNumber; }
    bool   getBlockStatus() const { return isBlocked; }

    bool verifyPIN(const string& inputPin) {
        if (isBlocked) throw runtime_error("This card is BLOCKED! Please contact Admin.");

        if (pin == inputPin) {
            pinAttempts = 0;
            SecuritySystem::saveCard(cardNumber, pin, isBlocked, pinAttempts);
            return true;
        }

        pinAttempts++;
        SecuritySystem::logEvent("Failed PIN attempt on Card: " + cardNumber);
        cout << "  Incorrect PIN! Attempts remaining: " << (3 - pinAttempts) << "\n";
        if (pinAttempts >= 3) {
            isBlocked = true;
            SecuritySystem::saveCard(cardNumber, pin, isBlocked, pinAttempts);
            SecuritySystem::logEvent("CRITICAL: Card " + cardNumber + " has been BLOCKED!");
            throw runtime_error("Card blocked due to 3 consecutive wrong PIN attempts!");
        }
        SecuritySystem::saveCard(cardNumber, pin, isBlocked, pinAttempts);
        return false;
    }

    void unblockCard() {
        isBlocked   = false;
        pinAttempts = 0;
        SecuritySystem::saveCard(cardNumber, pin, isBlocked, pinAttempts);
        cout << "  Card successfully unblocked.\n";
        SecuritySystem::logEvent("Admin unblocked Card: " + cardNumber);
    }

    void syncFromFile() {
        string savedPin;
        bool   savedBlocked;
        int    savedAttempts;
        if (SecuritySystem::loadCardData(cardNumber, savedPin, savedBlocked, savedAttempts)) {
            pin         = savedPin;
            isBlocked   = savedBlocked;
            pinAttempts = savedAttempts;
        }
    }
};

class ATM {
private:
    double dailyLimit;
    double currentDailyWithdrawn;

public:
    ATM() : dailyLimit(20000.0), currentDailyWithdrawn(0.0) {}

    void simulateATMWithdraw(Card& card, const string& inputPin, Account& acc, double amount) {
        card.syncFromFile();

        if (card.verifyPIN(inputPin)) {
            if (currentDailyWithdrawn + amount > dailyLimit) {
                throw runtime_error("Daily ATM withdrawal limit (20,000 BDT) exceeded!");
            }
            cout << "\n  [ATM Security] Verifying via Multi-Factor Authentication (MFA)...\n";
            if (SecuritySystem::verifyOTP()) {
                acc.withdraw(amount);
                currentDailyWithdrawn += amount;
                SecuritySystem::logEvent("ATM withdrawal of " + to_string(amount)
                                       + " from Acc: " + to_string(acc.getAccountNumber()));
                cout << "  Remaining daily ATM limit: "
                     << fixed << setprecision(2) << (dailyLimit - currentDailyWithdrawn) << " BDT\n";
            } else {
                throw runtime_error("ATM Transaction cancelled due to incorrect OTP!");
            }
        }
    }

    double getDailyLimit()          const { return dailyLimit; }
    double getDailyWithdrawnSoFar() const { return currentDailyWithdrawn; }
};

class User {
private:
    string   username;
    string   passwordHash;
    string   salt;
    int      loginAttempts;
    bool     isLocked;
    Account* linkedAccount;
    Card*    linkedCard;

public:
    // New user: generates a fresh salt and hashes the plain password immediately.
    // The raw password never gets stored anywhere, not even temporarily on disk.
    User(const string& user, const string& plainPass, Account* acc, Card* crd) {
        username      = user;
        salt          = SecuritySystem::generateSalt();
        passwordHash  = SecuritySystem::hashPassword(plainPass, salt);
        loginAttempts = 0;
        isLocked      = false;
        linkedAccount = acc;
        linkedCard    = crd;
        SecuritySystem::saveUser(username, passwordHash, salt, isLocked, loginAttempts,
                                 acc->getAccountNumber(), crd->getCardNumber());
    }

    // Rebuilding a user from disk: hash and salt are already computed, just load them.
    User(const string& user, const string& hash, const string& userSalt,
         bool locked, int attempts,
         Account* acc, Card* crd) {
        username      = user;
        passwordHash  = hash;
        salt          = userSalt;
        isLocked      = locked;
        loginAttempts = attempts;
        linkedAccount = acc;
        linkedCard    = crd;
    }

    string   getUsername()   const { return username; }
    bool     getLockStatus() const { return isLocked; }
    Account* getAccount()          { return linkedAccount; }
    Card*    getCard()             { return linkedCard; }

    bool verifyPassword(const string& inputPass) const {
        return passwordHash == SecuritySystem::hashPassword(inputPass, salt);
    }

    bool login(const string& inputUser, const string& inputPass) {
        if (isLocked) throw runtime_error("Your account is LOCKED due to multiple failed logins! Contact Admin.");

        if (username == inputUser && verifyPassword(inputPass)) {
            loginAttempts = 0;
            SecuritySystem::saveUser(username, passwordHash, salt, isLocked, loginAttempts,
                                     linkedAccount->getAccountNumber(), linkedCard->getCardNumber());
            return true;
        }

        if (username == inputUser) {
            loginAttempts++;
            SecuritySystem::logEvent("Failed login attempt on User: " + username);
            cout << "  Wrong password! Attempts remaining: " << (3 - loginAttempts) << "\n";
            if (loginAttempts >= 3) {
                isLocked = true;
                SecuritySystem::saveUser(username, passwordHash, salt, isLocked, loginAttempts,
                                        linkedAccount->getAccountNumber(), linkedCard->getCardNumber());
                SecuritySystem::logEvent("CRITICAL: User Account " + username + " has been LOCKED!");
                throw runtime_error("Account locked due to 3 failed login attempts!");
            }
            SecuritySystem::saveUser(username, passwordHash, salt, isLocked, loginAttempts,
                                    linkedAccount->getAccountNumber(), linkedCard->getCardNumber());
        }
        return false;
    }

    void unlockAccount() {
        isLocked      = false;
        loginAttempts = 0;
        SecuritySystem::saveUser(username, passwordHash, salt, isLocked, loginAttempts,
                                 linkedAccount->getAccountNumber(), linkedCard->getCardNumber());
        cout << "  User account successfully unlocked.\n";
        SecuritySystem::logEvent("Admin unlocked User Account: " + username);
    }
};

vector<User*>    globalUsers;
vector<Account*> globalAccounts;
vector<Card*>    globalCards;
int              nextAccountNumber = 1003;
int              nextCardSequence  = 1;

User* findUser(const string& username) {
    for (size_t i = 0; i < globalUsers.size(); i++)
        if (globalUsers[i]->getUsername() == username) return globalUsers[i];
    return nullptr;
}

Account* findAccount(int accNo) {
    for (size_t i = 0; i < globalAccounts.size(); i++)
        if (globalAccounts[i]->getAccountNumber() == accNo) return globalAccounts[i];
    return nullptr;
}

Card* findCard(const string& cardNo) {
    for (size_t i = 0; i < globalCards.size(); i++)
        if (globalCards[i]->getCardNumber() == cardNo) return globalCards[i];
    return nullptr;
}

// True if this username is already taken by an approved user or a pending application.
bool isUsernameTaken(const string& username) {
    if (findUser(username) != nullptr) return true;
    for (const AccountApplication& app : pendingApplications)
        if (app.username == username) return true;
    return false;
}

void loadAllDataFromFiles() {
    {
        vector<string> lines = SecuritySystem::readEncryptedFile(FILE_ACCOUNTS);
        for (const string& line : lines) {
            if (line.empty()) continue;
            istringstream ss(line);
            int no; double bal; string type;
            ss >> no >> bal >> type;
            globalAccounts.push_back(new Account(no, bal, type, true));
            if (no >= nextAccountNumber) nextAccountNumber = no + 1;
        }
    }

    {
        vector<string> lines = SecuritySystem::readEncryptedFile(FILE_CARDS);
        for (const string& line : lines) {
            if (line.empty()) continue;
            istringstream ss(line);
            string cno, cp; int bl, at;
            ss >> cno >> cp >> bl >> at;
            globalCards.push_back(new Card(cno, cp, (bl == 1), at));
        }
    }

    {
        vector<string> lines = SecuritySystem::readEncryptedFile(FILE_USERS);
        for (const string& line : lines) {
            if (line.empty()) continue;
            istringstream ss(line);
            string u, p, s, cn; int lk, la, an;
            ss >> u >> p >> s >> lk >> la >> an >> cn;
            Account* acc = findAccount(an);
            Card*    crd = findCard(cn);
            if (acc != nullptr && crd != nullptr) {
                globalUsers.push_back(new User(u, p, s, (lk == 1), la, acc, crd));
            }
        }
    }

    SecuritySystem::loadApplications(pendingApplications);

    if (!globalUsers.empty())
        cout << "  [System] Loaded " << globalUsers.size() << " user(s) from saved database.\n";
}

void setupDefaultDataIfNeeded() {
    if (!globalUsers.empty()) return;

    cout << "  [System] No existing database found. Setting up demo accounts...\n";

    Account* acc1 = new Account(1001, 25000.0, "Savings");
    Account* acc2 = new Account(1002, 5000.0,  "Current");
    Card*    crd1 = new Card("4321-8765-1111", "1234");
    Card*    crd2 = new Card("5555-6666-7777", "4321");

    globalAccounts.push_back(acc1);
    globalAccounts.push_back(acc2);
    globalCards.push_back(crd1);
    globalCards.push_back(crd2);

    globalUsers.push_back(new User("tarikul", "securePass", acc1, crd1));
    globalUsers.push_back(new User("target",  "targetPass", acc2, crd2));

    SecuritySystem::logEvent("Default demo accounts created.");
}

class BankPortal {
private:
    int inactivityCounter;

public:
    BankPortal() : inactivityCounter(0) {}

    void checkSessionTimeout() {
        if (inactivityCounter >= 3) {
            inactivityCounter = 0;
            SecuritySystem::logEvent("Session timed out due to successive invalid actions.");
            throw runtime_error("Session timed out! Please retry from Main Menu.");
        }
    }

    void incrementInactivity() { inactivityCounter++; }
    void resetInactivity()     { inactivityCounter = 0; }

    void applyForNewAccount() {
        string fullName, username, plainPass, nid, faceInput;

        cout << "\n--- Apply for a New SmartBank Account ---\n";
        cin.ignore(numeric_limits<streamsize>::max(), '\n');
        cout << "  Enter Full Name        : ";
        getline(cin, fullName);
        cout << "  Set Your Username      : ";
        cin >> username;

        if (isUsernameTaken(username)) {
            cout << "  Error: Username already taken! Choose a different one.\n";
            return;
        }

        cout << "  Set Your Password      : ";
        cin >> plainPass;
        cout << "  Enter NID Number       : ";
        cin >> nid;
        cout << "  Face Verification Scan (Type SCAN or YES): ";
        cin >> faceInput;

        // Hash the password right away, so a plain-text password is
        // never sitting in the applications file while awaiting approval.
        AccountApplication app;
        app.fullName = fullName;
        app.username = username;
        app.salt     = SecuritySystem::generateSalt();
        app.passwordHash = SecuritySystem::hashPassword(plainPass, app.salt);
        app.nidNumber = nid;
        app.faceVerificationStatus = "Biometric Match Verified (" + faceInput + ")";

        pendingApplications.push_back(app);
        SecuritySystem::saveAllApplications(pendingApplications);

        cout << "\n  [Application Submitted Successfully!]\n";
        cout << "  Thank you, " << fullName << ". Admin will verify NID: " << nid << " and approve soon.\n";
        SecuritySystem::logEvent("New Account Application submitted by: " + fullName);
    }

    void payBill(Account& acc, const string& billType, double amount) {
        cout << "\n--- Online Bill Payment Portal ---\n";
        if (amount <= 0) throw invalid_argument("Bill amount must be positive!");

        if (SecuritySystem::verifyOTP()) {
            acc.withdraw(amount);
            cout << "  " << billType << " bill successfully paid.\n";
            SecuritySystem::logEvent("Bill Paid: " + billType + " | Amount: " + to_string(amount));
        } else {
            throw runtime_error("2FA Verification failed! Bill payment cancelled.");
        }
    }

    void reviewPendingApplications() {
        if (pendingApplications.empty()) {
            cout << "\n  No pending applications found.\n";
            return;
        }

        cout << "\n--- List of Pending Account Applications ---\n";
        vector<AccountApplication> remaining;

        for (size_t i = 0; i < pendingApplications.size(); i++) {
            cout << "\n  Application #" << (i + 1) << "\n";
            cout << "  Name              : " << pendingApplications[i].fullName          << "\n";
            cout << "  Requested Username: " << pendingApplications[i].username          << "\n";
            cout << "  NID               : " << pendingApplications[i].nidNumber         << "\n";
            cout << "  Face Auth Status  : " << pendingApplications[i].faceVerificationStatus << "\n";
            cout << "  ------------------------------------------\n";

            char decision;
            cout << "  Review #" << (i + 1) << " -> [A]ccept or [D]eny? (A/D): ";
            cin >> decision;

            if (decision == 'A' || decision == 'a') {
                // Sequential counter guarantees a unique card number, unlike pure rand().
                string generatedCardNo = "CARD-" + to_string(9000 + nextCardSequence++);
                string defaultPin      = "1111";

                Account* newAcc  = new Account(nextAccountNumber++, 0.0, "Savings");
                Card*    newCard = new Card(generatedCardNo, defaultPin);

                globalAccounts.push_back(newAcc);
                globalCards.push_back(newCard);

                // Password is already hashed from application time, so we
                // load it directly instead of hashing it a second time.
                globalUsers.push_back(new User(
                    pendingApplications[i].username,
                    pendingApplications[i].passwordHash,
                    pendingApplications[i].salt,
                    false, 0,
                    newAcc, newCard
                ));
                SecuritySystem::saveUser(pendingApplications[i].username,
                    pendingApplications[i].passwordHash, pendingApplications[i].salt,
                    false, 0, newAcc->getAccountNumber(), generatedCardNo);

                cout << "\n  ============================================\n";
                cout << "  >>> APPLICATION APPROVED SUCCESSFULLY! <<<\n";
                cout << "  Assigned Account No : " << newAcc->getAccountNumber()       << "\n";
                cout << "  Assigned ATM Card No: " << generatedCardNo                  << "\n";
                cout << "  Default ATM PIN     : " << defaultPin << " (Change after first login)\n";
                cout << "  ============================================\n";

                SecuritySystem::logEvent("Admin APPROVED application for: " + pendingApplications[i].fullName);
            } else {
                remaining.push_back(pendingApplications[i]);
                cout << "  >>> Application Denied!\n";
                SecuritySystem::logEvent("Admin DENIED application for: " + pendingApplications[i].fullName);
            }
        }

        pendingApplications = remaining;
        SecuritySystem::saveAllApplications(pendingApplications);
    }
};

void clearInputBuffer() {
    cin.clear();
    cin.ignore(numeric_limits<streamsize>::max(), '\n');
}

int main() {
#ifdef _WIN32
    SetConsoleOutputCP(65001);
#endif
    srand((unsigned int)time(0));

    cout << "\n====================================\n";
    cout << "      SmartBank Secure System v2.2  \n";
    cout << "      File-Based Persistent Edition \n";
    cout << "====================================\n";

    loadAllDataFromFiles();
    setupDefaultDataIfNeeded();
    AdminAuth::ensureAdminPasswordExists();

    ATM        bankATM;
    BankPortal onlinePortal;

    int mainChoice;
    while (true) {
        cout << "\n====================================\n";
        cout << "      SmartBank Secure System       \n";
        cout << "====================================\n";
        cout << "  1. ATM Simulation\n";
        cout << "  2. Online Banking Portal\n";
        cout << "  3. Account Status Check (Login Required)\n";
        cout << "  4. Admin Panel (Security Control)\n";
        cout << "  5. Exit System\n";
        cout << "  Select your option: ";
        cin >> mainChoice;

        if (mainChoice == 5) {
            cout << "\n  Saving all data to files...\n";
            SecuritySystem::saveAllApplications(pendingApplications);
            SecuritySystem::logEvent("System shutdown by user.");
            cout << "  Shutting down SmartBank System... Goodbye!\n";
            break;
        }

        try {
            switch (mainChoice) {

                case 1: {
                    onlinePortal.resetInactivity();
                    cout << "\n--- ATM Simulation Module ---\n";
                    string user, inputPin;
                    double amount;

                    cout << "  Enter your Username to insert card: ";
                    cin >> user;

                    User* currentUser = findUser(user);
                    if (currentUser == nullptr) throw runtime_error("Card insertion failed! User not found in system.");
                    if (currentUser->getLockStatus()) throw runtime_error("User account is locked. Contact Admin.");

                    cout << "  Enter your ATM PIN  : ";
                    cin >> inputPin;
                    cout << "  Enter withdrawal amount (BDT): ";
                    cin >> amount;

                    bankATM.simulateATMWithdraw(*(currentUser->getCard()), inputPin, *(currentUser->getAccount()), amount);
                    break;
                }

                case 2: {
                    onlinePortal.resetInactivity();
                    cout << "\n--- Online Banking Portal ---\n";
                    cout << "  1. Login to Existing Account\n";
                    cout << "  2. Apply for a New Account (NID & Face Auth)\n";
                    cout << "  Enter sub-option: ";
                    int portalChoice;
                    cin >> portalChoice;

                    if (portalChoice == 2) {
                        onlinePortal.applyForNewAccount();

                    } else if (portalChoice == 1) {
                        string user, pass;
                        cout << "  Username: "; cin >> user;
                        cout << "  Password: "; cin >> pass;

                        User* currentUser = findUser(user);
                        if (currentUser != nullptr && currentUser->login(user, pass)) {
                            cout << "\n  Welcome, " << currentUser->getUsername() << "! Login Successful.\n";
                            SecuritySystem::logEvent("Successful login by: " + user);

                            cout << "  1. Fund Transfer\n";
                            cout << "  2. Utility Bill Payment\n";
                            cout << "  Enter choice: ";
                            int onlineChoice;
                            cin >> onlineChoice;

                            if (onlineChoice == 1) {
                                int targetAccNo;
                                double tAmount;
                                cout << "\n  Enter Destination Account Number: ";
                                cin >> targetAccNo;

                                Account* dest = findAccount(targetAccNo);
                                if (dest == nullptr) throw runtime_error("Target Account Number not found in system!");
                                if (dest->getAccountNumber() == currentUser->getAccount()->getAccountNumber())
                                    throw runtime_error("Cannot transfer to your own account!");

                                cout << "  Enter Amount (BDT) to transfer: ";
                                cin >> tAmount;

                                if (SecuritySystem::verifyOTP()) {
                                    currentUser->getAccount()->transfer(*dest, tAmount);
                                    cout << "  Fund transfer executed successfully to Account " << targetAccNo << ".\n";
                                    SecuritySystem::logEvent("Fund Transfer: " + user
                                        + " -> Acc " + to_string(targetAccNo)
                                        + " | Amount: " + to_string(tAmount));
                                } else {
                                    cout << "  Fund transfer aborted.\n";
                                }

                            } else if (onlineChoice == 2) {
                                string bType;
                                double bAmount;
                                cout << "  Enter Bill Type (e.g., Electricity/Gas): ";
                                cin >> bType;
                                cout << "  Enter Bill Amount (BDT): ";
                                cin >> bAmount;
                                onlinePortal.payBill(*(currentUser->getAccount()), bType, bAmount);
                            } else {
                                cout << "  Invalid sub-option!\n";
                            }
                        } else {
                            cout << "  Login Failed! Invalid credentials or account locked.\n";
                        }
                    } else {
                        cout << "  Invalid portal option!\n";
                    }
                    break;
                }

                case 3: {
                    onlinePortal.resetInactivity();
                    cout << "\n--- Security Verification for Account Status Check ---\n";
                    string user, pass;
                    cout << "  Enter Username: "; cin >> user;
                    cout << "  Enter Password: "; cin >> pass;

                    User* currentUser = findUser(user);
                    if (currentUser != nullptr && currentUser->verifyPassword(pass)) {
                        if (currentUser->getLockStatus()) {
                            cout << "  [Access Denied]: Your account is currently locked.\n";
                        } else {
                            cout << "\n--- Your Current Account Status ---\n";
                            cout << "  Username    : " << currentUser->getUsername()               << "\n";
                            cout << "  Account No  : " << currentUser->getAccount()->getAccountNumber() << "\n";
                            cout << "  Account Type: " << currentUser->getAccount()->getAccountType()   << "\n";
                            cout << "  Card Number : " << currentUser->getCard()->getCardNumber()        << "\n";
                            cout << "  Card Status : " << (currentUser->getCard()->getBlockStatus() ? "BLOCKED" : "Active") << "\n";
                            currentUser->getAccount()->displayBalance();
                        }
                    } else {
                        cout << "  [Access Denied]: Invalid Username or Password!\n";
                        SecuritySystem::logEvent("Unauthorized account status check for: " + user);
                    }
                    break;
                }

                case 4: {
                    onlinePortal.resetInactivity();
                    string adminPass;
                    cout << "\n  Enter Admin Master Password: ";
                    cin >> adminPass;

                    if (AdminAuth::verify(adminPass)) {
                        SecuritySystem::logEvent("Admin panel accessed.");
                        int admChoice;
                        cout << "\n--- Admin Control Panel ---\n";
                        cout << "  1. Unblock ATM Card\n";
                        cout << "  2. Unlock User Account\n";
                        cout << "  3. View Decrypted Transaction History\n";
                        cout << "  4. View & Review Pending Account Applications\n";
                        cout << "  5. View All Registered Users Summary\n";
                        cout << "  Enter choice: ";
                        cin >> admChoice;

                        if (admChoice == 1) {
                            string cNo;
                            cout << "  Enter Card Number to unblock: ";
                            cin >> cNo;
                            bool cardFound = false;
                            for (size_t i = 0; i < globalUsers.size(); i++) {
                                if (globalUsers[i]->getCard()->getCardNumber() == cNo) {
                                    globalUsers[i]->getCard()->unblockCard();
                                    cardFound = true;
                                }
                            }
                            if (!cardFound) cout << "  Card not found!\n";

                        } else if (admChoice == 2) {
                            string uName;
                            cout << "  Enter Username to unlock: ";
                            cin >> uName;
                            User* u = findUser(uName);
                            if (u != nullptr) u->unlockAccount();
                            else cout << "  User not found!\n";

                        } else if (admChoice == 3) {
                            SecuritySystem::viewAllTransactions();

                        } else if (admChoice == 4) {
                            onlinePortal.reviewPendingApplications();

                        } else if (admChoice == 5) {
                            cout << "\n--- All Registered Users Summary ---\n";
                            for (size_t i = 0; i < globalUsers.size(); i++) {
                                cout << "  [" << (i + 1) << "] "
                                     << globalUsers[i]->getUsername()
                                     << " | Acc: " << globalUsers[i]->getAccount()->getAccountNumber()
                                     << " | Bal: " << fixed << setprecision(2)
                                     << globalUsers[i]->getAccount()->getBalance() << " BDT"
                                     << " | Card: " << globalUsers[i]->getCard()->getCardNumber()
                                     << " | Status: " << (globalUsers[i]->getLockStatus() ? "LOCKED" : "Active")
                                     << "\n";
                            }
                            cout << "  Total Users: " << globalUsers.size() << "\n";

                        } else {
                            cout << "  Invalid admin choice!\n";
                        }

                    } else {
                        cout << "  Incorrect Admin Password! Access Denied.\n";
                        SecuritySystem::logEvent("ALERT: Failed Admin Panel access attempt.");
                    }
                    break;
                }

                default:
                    onlinePortal.incrementInactivity();
                    onlinePortal.checkSessionTimeout();
                    cout << "  Invalid Option! Please select 1-5.\n";
            }
        }
        catch (const exception& e) {
            cout << "\n  [SECURITY ALERT / ERROR]: " << e.what() << "\n";
            SecuritySystem::logEvent("Exception caught: " + string(e.what()));
        }
    }

    for (size_t i = 0; i < globalUsers.size();    i++) delete globalUsers[i];
    for (size_t i = 0; i < globalAccounts.size(); i++) delete globalAccounts[i];
    for (size_t i = 0; i < globalCards.size();    i++) delete globalCards[i];

    return 0;
}
