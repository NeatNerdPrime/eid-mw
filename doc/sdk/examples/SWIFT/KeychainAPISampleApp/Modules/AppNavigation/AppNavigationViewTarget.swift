//

import Foundation

enum AppNavigationViewTarget {
    case certificateRetrieval
    case certificateSelection
    case signingOperationSelection(KeychainIdentity)
    case singleElementSigning(KeychainIdentity)
    case bulkSigning(KeychainIdentity)
}
