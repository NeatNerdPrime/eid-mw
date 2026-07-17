//

import Foundation

enum SingleElementSigningViewModelState {
    case waitingForInput
    case waitingForSignature
    case signatureCompleted(String)
    case error(String)
}
