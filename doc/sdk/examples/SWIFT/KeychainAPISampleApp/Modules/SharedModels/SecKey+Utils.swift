//

import Foundation
import Security

extension SecKey {
    var tokenId: String? {
        let attrs = SecKeyCopyAttributes(self) as? [CFString: Any]
        return attrs?[kSecAttrTokenID] as? String
    }
}
