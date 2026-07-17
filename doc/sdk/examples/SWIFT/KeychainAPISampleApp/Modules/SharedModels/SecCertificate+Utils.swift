//

import Foundation
import CryptoKit
import Security

public extension SecCertificate {
    var summary: String {
        let summary = (SecCertificateCopySubjectSummary(self) as String?) ?? "Certificate"
        let issuerCommonName = self.issuerCommonName ?? "Unknown"
        return "\(summary) (\(issuerCommonName))"
    }
    
    var notValidBefore: Date? {
        guard
            let values = SecCertificateCopyValues(
                self,
                [kSecOIDX509V1ValidityNotBefore] as CFArray,
                nil
            ) as? [CFString: Any],
            let validityDict = values[kSecOIDX509V1ValidityNotBefore] as? [CFString: Any],
            let dateValue = validityDict[kSecPropertyKeyValue] as? Double
        else {
            return nil
        }
        
        return Date(timeIntervalSinceReferenceDate: dateValue)
    }
    
    var notValidAfter: Date? {
        guard
            let values = SecCertificateCopyValues(
                self,
                [kSecOIDX509V1ValidityNotAfter] as CFArray,
                nil
            ) as? [CFString: Any],
            let validityDict = values[kSecOIDX509V1ValidityNotAfter] as? [CFString: Any],
            let dateValue = validityDict[kSecPropertyKeyValue] as? Double
        else {
            return nil
        }
        
        return Date(timeIntervalSinceReferenceDate: dateValue)
    }
    
    var isValid: Bool {
        guard let notValidBefore = self.notValidBefore,
              let notValidAfter = self.notValidAfter
        else { return false }
        
        return notValidBefore < Date() && notValidAfter > Date()
    }
    
    var issuerCommonName: String? {
        let keys = [kSecOIDX509V1IssuerName] as CFArray

        guard let values = SecCertificateCopyValues(self, keys, nil) as? [CFString: Any],
              let issuer = values[kSecOIDX509V1IssuerName] as? [CFString: Any],
              let issuerValue = issuer[kSecPropertyKeyValue] as? [[CFString: Any]]
        else {
            return nil
        }

        for attribute in issuerValue {
            if let label = attribute[kSecPropertyKeyLabel] as? String,
               label == "2.5.4.3",
               let value = attribute[kSecPropertyKeyValue] as? String {
                return value
            }
        }

        return nil
    }
}
