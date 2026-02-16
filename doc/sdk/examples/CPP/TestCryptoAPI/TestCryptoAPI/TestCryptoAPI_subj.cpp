// TestCryptoAPI.cpp : Defines the entry point for the console application.
//
#pragma comment(lib, "crypt32.lib")

#include <stdio.h>
#include <windows.h>
#include <wincrypt.h>
#include <ncrypt.h>
#include <vector>
#include <iostream>
#include <fstream>

#pragma comment(lib, "ncrypt.lib")
#pragma comment(lib, "crypt32.lib")


#include <unordered_map>

#include <filesystem> // C++ 17 to have absolute path from relatove

namespace fs = std::filesystem;


void PrintErrorMessage(DWORD errorCode) {
	char* messageBuffer = nullptr;
	FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL, errorCode, 0, (LPSTR)&messageBuffer, 0, NULL);
	if (messageBuffer) {
		std::cout << "Error " << "0x" << std::hex << errorCode << ": " << messageBuffer;
		LocalFree(messageBuffer);
	}
	else {
		std::cout << "Unknown error code: " << errorCode << std::endl;
	}
}

void ListSigningCertificates(std::vector<PCCERT_CONTEXT>& certList) {
	HCERTSTORE hStore = CertOpenSystemStore(0, L"MY");
	if (!hStore) {
		printf("Failed to open certificate store.\n");
		return;
	}

	PCCERT_CONTEXT pCert = NULL;
	int index = 0;

	printf("Available signing certificates:\n");
	while ((pCert = CertEnumCertificatesInStore(hStore, pCert)) != NULL) {
		// Check if the certificate has a private key (i.e., usable for signing)
		DWORD dwSize = 0;
		if (CertGetCertificateContextProperty(pCert, CERT_KEY_PROV_INFO_PROP_ID, NULL, &dwSize)) {
			certList.push_back(CertDuplicateCertificateContext(pCert)); // Store a copy
			wchar_t subjectName[256];
			CertGetNameStringW(pCert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, subjectName, 256);
			wprintf(L"[%d] %s\n", index, subjectName);
			index++;
		}
	}

	//CertCloseStore(hStore, 0);
}

// Function to find private key from cert by subject name
NCRYPT_KEY_HANDLE LoadKeyHandleBySubjectName3(const std::wstring& subjectName)
{
	HCERTSTORE hStore = nullptr;
	PCCERT_CONTEXT pCertCtx = nullptr;
	NCRYPT_KEY_HANDLE hKey = 0;
	BOOL fCallerFreeProvOrNCryptKey = FALSE;

	// Open the "MY" certificate store (Current User)
	hStore = CertOpenStore(CERT_STORE_PROV_SYSTEM, 0, NULL,
		CERT_SYSTEM_STORE_CURRENT_USER, L"MY");

	if (!hStore) {
		std::wcerr << L"[ERROR] Failed to open cert store: " << GetLastError() << std::endl;
		return 0;
	}

	// Search for cert with exact subject name match
	while ((pCertCtx = CertFindCertificateInStore(
		hStore,
		X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
		0,
		CERT_FIND_SUBJECT_STR,
		subjectName.c_str(),
		pCertCtx)) != nullptr) {

		std::wcout << L"[INFO] Found cert: " << subjectName << std::endl;

		// Try to get the private key associated with this cert
		if (CryptAcquireCertificatePrivateKey(
			pCertCtx,
			CRYPT_ACQUIRE_SILENT_FLAG | CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG,
			NULL,
			&hKey,
			NULL,
			&fCallerFreeProvOrNCryptKey)) {

			std::wcout << L"[INFO] Found private key (NCRYPT) handle." << std::endl;

			// If store and cert context don't need to be freed anymore
			CertFreeCertificateContext(pCertCtx);
			CertCloseStore(hStore, 0);
			return hKey;
		}
		else {
			std::wcerr << L"[WARN] No private key or failed to access it. Error: " << GetLastError() << std::endl;
		}
	}

	std::wcerr << L"[ERROR] No matching cert with private key for subject: " << subjectName << std::endl;

	if (pCertCtx) CertFreeCertificateContext(pCertCtx);
	if (hStore) CertCloseStore(hStore, 0);

	return 0;
}


void ListKeysFromBaseCSP()
{
	NCRYPT_PROV_HANDLE hProvider = 0;
	NCRYPT_KEY_HANDLE hKey = 0;
	NCryptKeyName* pKeyName = nullptr;
	PVOID pEnumState = nullptr;
	SECURITY_STATUS status;
	LONG scStatus;

	// Open the Base CSP provider
	status = NCryptOpenStorageProvider(&hProvider, MS_SCARD_PROV, 0);
	if (status != ERROR_SUCCESS) {
		std::wcout << L"Failed to open provider. Error: " << status << std::endl;
		return;
	}

	std::wcout << L"Base CSP Opened Successfully!\nEnumerating Keys...\n";

	// Enumerate keys
	while ((status = NCryptEnumKeys(hProvider, NULL, &pKeyName, &pEnumState, 0/*NCRYPT_MACHINE_KEY_FLAG*/)) == ERROR_SUCCESS) {
		std::wcout << std::endl;
		std::wcout << L"Key Name: " << pKeyName->pszName << std::endl;
		std::wcout << L"  Algorithm: " << (pKeyName->pszAlgid ? pKeyName->pszAlgid : L"(Unknown)") << std::endl;

		// Open key to check additional properties
		if (NCryptOpenKey(hProvider, &hKey, pKeyName->pszName, 0, 0) == ERROR_SUCCESS) {
			DWORD keyUsage = 0, keyUsageSize = 0;

			if (NCryptGetProperty(hKey, NCRYPT_KEY_USAGE_PROPERTY,
				(PBYTE)&keyUsage, sizeof(DWORD), &keyUsageSize, 0) == ERROR_SUCCESS) {
				if (keyUsage & NCRYPT_ALLOW_SIGNING_FLAG) {
					std::wcout << L"  [v] Key supports signing" << std::endl;
				}
				else {
					std::wcout << L"  [x] Key does NOT support signing" << std::endl;
				}
			}

			NCryptFreeObject(hKey);
		}
		else {
			std::wcout << L"  Could not open key!" << std::endl;
		}

		NCryptFreeBuffer(pKeyName);
	}

	// Cleanup
	NCryptFreeObject(hProvider);
	std::wcout << L"Key Enumeration Completed!" << std::endl;
}

NCRYPT_KEY_HANDLE BaseCSPLoadFirstKey()
{
	NCRYPT_PROV_HANDLE hProvider = 0;
	NCRYPT_KEY_HANDLE hKey = 0;
	NCryptKeyName* pKeyName = nullptr;
	PVOID pEnumState = nullptr;
	SECURITY_STATUS status;

	// Open the Base CSP provider
	status = NCryptOpenStorageProvider(&hProvider, MS_SCARD_PROV, 0);
	if (status != ERROR_SUCCESS) {
		std::wcout << L"Failed to open provider. Error: " << status << std::endl;
		return 0;
	}

	std::wcout << L"Base CSP Opened Successfully!\nLoad first signing key found...\n";

	// Enumerate keys
	while ((status = NCryptEnumKeys(hProvider, NULL, &pKeyName, &pEnumState, 0)) == ERROR_SUCCESS) {
		std::wcout << std::endl;
		std::wcout << L"Key Name: " << pKeyName->pszName << std::endl;
		std::wcout << L"  Algorithm: " << (pKeyName->pszAlgid ? pKeyName->pszAlgid : L"(Unknown)") << std::endl;

		// Open key to check additional properties
		if (NCryptOpenKey(hProvider, &hKey, pKeyName->pszName, 0, 0) == ERROR_SUCCESS) {
			DWORD keyUsage = 0, keyUsageSize = 0;

			if (NCryptGetProperty(hKey, NCRYPT_KEY_USAGE_PROPERTY,
				(PBYTE)&keyUsage, sizeof(DWORD), &keyUsageSize, 0) == ERROR_SUCCESS) {
				if (keyUsage & NCRYPT_ALLOW_SIGNING_FLAG) {
					std::wcout << L"  [v] Key supports signing" << std::endl;
					NCryptFreeBuffer(pKeyName);
					NCryptFreeObject(hProvider);
					return hKey;
				}
				else {
					std::wcout << L"  [x] Key does NOT support signing" << std::endl;
				}
			}

			NCryptFreeObject(hKey);
		}
		else {
			std::wcout << L"  Could not open key!" << std::endl;
		}

		NCryptFreeBuffer(pKeyName);
	}

	// Cleanup
	NCryptFreeObject(hProvider);
	std::wcout << L"No Signing key found on smartcard" << std::endl;
	return 0;
}

void listProviders(void)
{
	//-------------------------------------------------------------------
	// Declare and initialize variables.

	HCRYPTPROV hProv = 0;
	LPTSTR pszName;
	DWORD dwType;
	DWORD cbName = 0;
	DWORD dwIndex = 0;
	DWORD dwIncrement = sizeof(DWORD);
	DWORD dwFlags = CRYPT_FIRST;
	DWORD dwParam = PP_CLIENT_HWND;
	CHAR* pszAlgType = NULL;
	BOOL fMore = TRUE;

	//--------------------------------------------------------------
// Print header lines for providers.
	printf("\n\nListing Available Providers.\n");
	printf("Provider type    Provider Name\n");

	//---------------------------------------------------------------
	// Loop through enumerating providers.
	dwIndex = 0;
	while (CryptEnumProvidersW(
		dwIndex,
		NULL,
		0,
		&dwType,
		NULL,
		&cbName))
	{
		//-----------------------------------------------------------
		// cbName is the length of the name of the next provider.
		// Allocate memory in a buffer to retrieve that name.
		if (!(pszName = (LPTSTR)LocalAlloc(LMEM_ZEROINIT, cbName)))
		{
			printf("ERROR - LocalAlloc failed!");
		}

		//-----------------------------------------------------------
		// Get the provider name.
		if (CryptEnumProviders(
			dwIndex++,
			NULL,
			0,
			&dwType,
			pszName,
			&cbName))
		{
			printf("     %4.0d        %S\n", dwType, pszName);
		}
		else
		{
			printf("ERROR - CryptEnumProviders");
		}

		LocalFree(pszName);
	} // End while loop.
}

NCRYPT_KEY_HANDLE GetKeyHandleFromCert(PCCERT_CONTEXT pCertContext) {
	NCRYPT_PROV_HANDLE hProvider;
	NCRYPT_KEY_HANDLE hKey;
	CRYPT_KEY_PROV_INFO* pKeyInfo = NULL;
	DWORD dwSize = 0;
	DWORD dwKeySpec = 0;
	BOOL fCallerFreeKey = FALSE;


	if (!CertGetCertificateContextProperty(pCertContext, CERT_KEY_PROV_INFO_PROP_ID, NULL, &dwSize)) {
		printf("Failed to get key provider info.\n");
		return NULL;
	}

	pKeyInfo = (CRYPT_KEY_PROV_INFO*)malloc(dwSize);
	if (!CertGetCertificateContextProperty(pCertContext, CERT_KEY_PROV_INFO_PROP_ID, pKeyInfo, &dwSize)) {
		printf("Failed to retrieve key provider info.\n");
		free(pKeyInfo);
		return NULL;
	}

	SECURITY_STATUS status = NCryptOpenStorageProvider(&hProvider, pKeyInfo->pwszProvName, 0);
	if (status != ERROR_SUCCESS) {
		printf("Failed to open provider. Error: 0x%08X\n", status);
		free(pKeyInfo);
		return NULL;
	}

	printf("Provider for chosen certificate : %S\n", pKeyInfo->pwszProvName);

	status = NCryptOpenKey(hProvider, &hKey, pKeyInfo->pwszContainerName, 0, 0);

	if (status == NTE_DEVICE_NOT_READY) {

		printf("Smart card required! Please insert the device (%0x).\n", status);
	}
	else if (status != ERROR_SUCCESS) {
		printf("Error opening key.\n");
		PrintErrorMessage(status);
		hKey = NULL;
	}
	else {
		printf("dwflags: %d\n", pKeyInfo->dwFlags);
		printf("dwKeySpec: %d\n", pKeyInfo->dwKeySpec);

		DWORD keyUsage = 0, keyUsageSize = 0;
		if (NCryptGetProperty(hKey, NCRYPT_KEY_USAGE_PROPERTY,
			(PBYTE)&keyUsage, sizeof(DWORD), &keyUsageSize, 0) == ERROR_SUCCESS) {
			if (keyUsage & NCRYPT_ALLOW_SIGNING_FLAG) {
				std::wcout << L"  [v] Key supports signing" << std::endl;
			}
			else {
				std::wcout << L"  [x] Key does NOT support signing" << std::endl;
			}
		}

		WCHAR algName[128] = { 0 };
		DWORD algNameSize = 0;

		if (NCryptGetProperty(hKey, NCRYPT_ALGORITHM_PROPERTY,
			(PBYTE)algName, sizeof(algName), &algNameSize, 0) == ERROR_SUCCESS) {
			std::wcout << L"  Algorithm: " << algName << std::endl;
		}
		else {
			std::wcout << L"  Algorithm: (Unknown)" << std::endl;
		}
	}

	free(pKeyInfo);
	NCryptFreeObject(hProvider);
	return hKey;
}


PBYTE generateHash(size_t size) {
	if (size == 0) return nullptr;

	PBYTE buffer = new BYTE[size];
	if (!buffer) return nullptr; // Handle allocation failure

	for (size_t i = 0; i < size; ++i) {
		buffer[i] = static_cast<BYTE>(i + 1); // 0x01, 0x02, ..., 0x30 (48 in decimal)
	}

	return buffer;
}

SECURITY_STATUS SignHashWithKey(NCRYPT_KEY_HANDLE hKey) {

#define HASHALGO   BCRYPT_SHA384_ALGORITHM;
	DWORD hashSize = 48;
	PBYTE hash = generateHash(hashSize);

// in case of RSA signatures, define padding type
#define PKCS1_PADDING //ifnot => USE PSS
#ifdef PKCS1_PADDING
	BCRYPT_PKCS1_PADDING_INFO paddingInfo;
	BCRYPT_PKCS1_PADDING_INFO* pPaddingInfo = &paddingInfo;
	paddingInfo.pszAlgId = HASHALGO;
	DWORD dwflags = NCRYPT_PAD_PKCS1_FLAG;
#else //PSS_PADDING
	BCRYPT_PSS_PADDING_INFO paddingInfo;
	BCRYPT_PSS_PADDING_INFO* pPaddingInfo = &paddingInfo;
	paddingInfo.pszAlgId = HASHALGO;
	paddingInfo.cbSalt = hashSize;
	DWORD dwflags = NCRYPT_PAD_PSS_FLAG;
#endif

	PBYTE pbSignature = NULL;
	DWORD cbSignature = 0;
	SECURITY_STATUS status;
	DWORD cbResult = 0;
	WCHAR szAlgorithm[64] = { 0 };
	bool isRSA = false;
	
	// Get the algorithm name
	status = NCryptGetProperty(hKey, NCRYPT_ALGORITHM_GROUP_PROPERTY, (PBYTE)szAlgorithm, sizeof(szAlgorithm), &cbResult, 0);
	if (status != ERROR_SUCCESS) {
		printf("NCryptGetProperty failed\n");
		PrintErrorMessage(status);
	}
	else {
		wprintf(L"Algorithm Name: %s\n", szAlgorithm);

		// Compare with expected values
		if (wcscmp(szAlgorithm, L"RSA") == 0) {
			wprintf(L"Key algorithm is RSA\n");
			isRSA = true;
		}
		else if (wcscmp(szAlgorithm, L"ECDSA") == 0) {
			wprintf(L"Key algorithm is ECDSA\n");
			dwflags = 0;
			pPaddingInfo = NULL;
		}
		else {
			wprintf(L"Unknown algorithm: %s\n", szAlgorithm);
		}
	}

	// First call to get the required buffer size
	status = NCryptSignHash(hKey, pPaddingInfo, hash, hashSize, NULL, 0, &cbResult, dwflags);
	if (status != ERROR_SUCCESS) {
		std::wcout << L"Failed to get signature size. Error: " << status << std::endl;
		PrintErrorMessage(status);
		return status;
	}

	// Allocate memory for the signature
	pbSignature = new BYTE[cbResult];
	if (!pbSignature) return status;

	// Sign the hash
	status = NCryptSignHash(hKey, pPaddingInfo, hash, hashSize, pbSignature, cbResult, &cbSignature, dwflags);
	if (status != ERROR_SUCCESS) {
		std::wcout << L"Failed to sign hash" << std::endl;
		PrintErrorMessage(status);
		delete[] pbSignature;
		return status;
	}

	std::wcout << L"Signature generated successfully. Size: " << cbSignature << " bytes." << std::endl;

#if 0
	std::string file = "signature.bin";
	std::ofstream outFile(file, std::ios::binary);
	outFile.write(reinterpret_cast<const char*>(pbSignature), cbSignature);
	outFile.close();
#endif

#if 0 //test invalid signature
		hash[0] = hash[0] ^ hash[0];
#endif 

	// Verify the signature
	status = NCryptVerifySignature(
		hKey,                   // Handle to the public key
		pPaddingInfo,                   // No padding info
		const_cast<PBYTE>(hash), // Remove const qualifier from hash
		hashSize,               // Size of the hash
		const_cast<PBYTE>(pbSignature), // Remove const qualifier from signature
		cbSignature,                // Size of the signature
		dwflags                       // Flags
	);
	if (status != ERROR_SUCCESS) {
		PrintErrorMessage(status);
	}
	else {
		printf("Signature validation OK\n");
	}

	//change the hash to test corrupt signature
	return status;
}

bool VerifySignature(PCCERT_CONTEXT pCert, const BYTE* hash, DWORD hashSize, const BYTE* signature, DWORD sigSize) {
	// Get the public key from the certificate
	HCRYPTPROV_OR_NCRYPT_KEY_HANDLE hKey = NULL;
	DWORD keySpec;
	BOOL freeKey = FALSE;

	if (!CryptAcquireCertificatePrivateKey(
		pCert,
		CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG /* | CRYPT_ACQUIRE_SILENT_FLAG*/,
		NULL,
		&hKey,
		&keySpec,
		&freeKey)) {
	 	printf("Failed to acquire certificate private key.\n");
		return false;
	}

	// Verify the signature
	SECURITY_STATUS status = NCryptVerifySignature(
		hKey,                   // Handle to the public key
		NULL,                   // No padding info
		const_cast<PBYTE>(hash), // Remove const qualifier from hash
		hashSize,               // Size of the hash
		const_cast<PBYTE>(signature), // Remove const qualifier from signature
		sigSize,                // Size of the signature
		0                       // Flags
	);

	if (freeKey) {
		NCryptFreeObject(hKey);
	}

	if (status != ERROR_SUCCESS) {
		printf("Signature verification failed. Error: 0x%08X\n", status);
		return false;
	}

	return true;
}

void printMenu() {
	std::cerr << "Usage:\n";
	std::cerr << "  TestCryptoApi --subj <path_to_key.p12>\n";
}


int main(int argc, char* argv[]) {

	if (argc < 2) {
		printMenu();
		return 1;
	}
	std::string command = argv[1];

	std::filesystem::path pfxFullPath;
	std::filesystem::path cwd = std::filesystem::current_path(); // caller's dir

	std::wstring subject;
	if (argc >= 3 && std::string(argv[1]) == "--subj") {
		std::string raw = argv[2];
		pfxFullPath = cwd / raw;
		pfxFullPath = std::filesystem::absolute(pfxFullPath);
		std::cout << "Resolved PFX path: " << pfxFullPath << std::endl;
		if (!std::filesystem::exists(pfxFullPath)) {
			std::cerr << "[FATAL] Key file not found: " << pfxFullPath << std::endl;
			return -1; ;
		}

		std::string fileName = pfxFullPath.filename().string();      // user2.p12
		std::string baseName = pfxFullPath.stem().string();          // user2
		std::transform(baseName.begin(), baseName.end(), baseName.begin(), ::tolower);

		std::unordered_map<std::string, std::wstring> subjectMap = {
		{"user1", L"User1"},
		{"user2", L"User2"},
		{"user3", L"User3"},
		{"user4", L"User4"},
		{"user5", L"User5"}
		};

		auto it = subjectMap.find(baseName);
		if (it == subjectMap.end()) {
			std::wcerr << L"[ERROR] Unknown subject for: " << baseName.c_str() << std::endl;
			return -1;
		}
		subject = it->second;


	}
	else {
		std::filesystem::path exePath = std::filesystem::current_path();
		pfxFullPath = exePath / "keys" / "user.p12"; // fallback default
		std::cout << "Default PFX path: " << pfxFullPath << std::endl;
	}


	listProviders();

	//in arm64, when using minidriver arm64 this works
	//minidriver has to be be built in arm64EC mode when we (or Adobe Reader) is built in x64 mode
	//otherise the minidriver only works for some part, but keys are not seen by Windows smartcard base CSP
	ListKeysFromBaseCSP();
	//return 0;
	std::vector<PCCERT_CONTEXT> certList;
	ListSigningCertificates(certList);
#if 0
	if (certList.empty()) {
		printf("No signing certificates found.\n");
		return 1;
	}

	unsigned int choice;
	printf("Select a certificate index: ");
	scanf_s("%d", &choice);

	if (choice >= certList.size()) {
		printf("Invalid choice.\n");
		return 1;
	}

	NCRYPT_KEY_HANDLE hKey = GetKeyHandleFromCert(certList[choice]);
#elif 0
	NCRYPT_KEY_HANDLE hKey = BaseCSPLoadFirstKey();
#else
	//NCRYPT_KEY_HANDLE hKey = LoadKeyHandleBySubjectName3(L"User1");
	std::wcout << "Now loading key for Subject: " << subject << std::endl;
	NCRYPT_KEY_HANDLE hKey = LoadKeyHandleBySubjectName3(subject);
#endif

	if (hKey) {
		SignHashWithKey(hKey);
		NCryptFreeObject(hKey);
	}

	for (auto cert : certList) {
		CertFreeCertificateContext(cert);
	}

	return 0;
}
