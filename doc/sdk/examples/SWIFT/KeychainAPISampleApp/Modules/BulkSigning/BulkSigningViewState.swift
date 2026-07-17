//

import Foundation

enum BulkSigningViewState {
    case filesSelection
    case waitingForSignature
    case signatureCompleted(String)
    case error(String)
}
