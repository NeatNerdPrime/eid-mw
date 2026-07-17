//

import Foundation
import CryptoKit

struct BulkSigningRequest: Encodable {
    let version: String = "1.0"
    let tokenId: String
    let signData: [Document]
    
    init(tokenId: String, urls: [URL]) {
        self.tokenId = tokenId
        self.signData = urls.compactMap { url in
            guard let data = try? Data(contentsOf: url)
            else { return nil }
            
            let hash = Data(SHA256.hash(data: data)).base64EncodedString()
            return Document(hash: hash, docName: url.lastPathComponent)
        }
    }
}

extension BulkSigningRequest {
    struct Document: Encodable {
        let hash: String
        let docName: String
        
        enum CodingKeys: String, CodingKey {
            case hash = "hash_base64"
            case docName = "docName"
        }
    }
}
