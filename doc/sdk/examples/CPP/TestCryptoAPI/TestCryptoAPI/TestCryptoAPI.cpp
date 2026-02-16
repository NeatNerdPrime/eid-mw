// TestCryptoAPI.cpp : Basic sample to list Providers, certificates and perform test signature using BaseCSP.
// 
// can be used for testing eID signatures as well as Remote Signatures authenticated by eID
// 
// After installation of new eID middleware including Remote Signing capabilities, get a certificate first and then start this test app.
//
#include <stdio.h>
#include <windows.h>
#include <wincrypt.h>
#include <ncrypt.h>
#include <vector>
#include <iostream>

#pragma comment(lib, "ncrypt.lib")
#pragma comment(lib, "crypt32.lib")

#include <unordered_map>

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

	printf("\nAvailable signing certificates:\n");
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

	CertCloseStore(hStore, 0);
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
	}
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

#define HASHALGO   BCRYPT_SHA256_ALGORITHM;
//#define HASHALGO   BCRYPT_SHA348_ALGORITHM;
#define HASHSIZE   0x20
		;
	PBYTE hash = generateHash(HASHSIZE);

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
	status = NCryptSignHash(hKey, pPaddingInfo, hash, HASHSIZE, NULL, 0, &cbResult, dwflags);
	if (status != ERROR_SUCCESS) {
		std::wcout << L"Failed to get signature size. Error: " << status << std::endl;
		PrintErrorMessage(status);
		return status;
	}

	// Allocate memory for the signature
	pbSignature = new BYTE[cbResult];
	if (!pbSignature) return status;

	// Sign the hash
	status = NCryptSignHash(hKey, pPaddingInfo, hash, HASHSIZE, pbSignature, cbResult, &cbSignature, dwflags);
	if (status != ERROR_SUCCESS) {
		std::wcout << L"Failed to sign hash" << std::endl;
		PrintErrorMessage(status);
		delete[] pbSignature;
		return status;
	}

	std::wcout << L"Signature generated successfully. Size: " << cbSignature << " bytes." << std::endl; 

	// Verify the signature
	status = NCryptVerifySignature(
		hKey,							// Handle to the public key
		pPaddingInfo,                   // No padding info
		const_cast<PBYTE>(hash),		// Remove const qualifier from hash
		HASHSIZE,						// Size of the hash
		const_cast<PBYTE>(pbSignature), // Remove const qualifier from signature
		cbSignature,					// Size of the signature
		dwflags							// Flags
	);
	if (status != ERROR_SUCCESS) {
		PrintErrorMessage(status);
	}
	else {
		printf("Signature validation OK\n");
	}

	return status;
}

int main(int argc, char* argv[]) {

	listProviders();

	ListKeysFromBaseCSP();

	std::vector<PCCERT_CONTEXT> certList;
	ListSigningCertificates(certList);
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
	if (hKey) {
		SignHashWithKey(hKey);
		NCryptFreeObject(hKey);
	}

	for (auto cert : certList) {
		CertFreeCertificateContext(cert);
	}

	return 0;
}
