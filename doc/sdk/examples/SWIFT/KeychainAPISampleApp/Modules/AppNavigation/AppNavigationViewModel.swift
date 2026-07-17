//

import Foundation

@Observable
class AppNavigationViewModel {
    // MARK: - Observable properties
    private(set) var viewTarget: AppNavigationViewTarget = .certificateSelection
}

// MARK: - Derived models
extension AppNavigationViewModel {
    var certificateRetrievalViewModel: CertificateRetrievalViewModel {
        .init(retrievalCompleted: {
            self.viewTarget = .certificateSelection
        })
    }
    var certificateSelectionViewModel: CertificateSelectionViewModel {
        .init(
            backRequested: {
                self.viewTarget = .certificateRetrieval
            },
            identitySelected: { identity in
                self.viewTarget = .signingOperationSelection(identity)
            }
        )
    }
    
    func signingOperationSelectionViewModel(identity: KeychainIdentity) -> SigningOperationSelectionViewModel {
        .init(operationSelected: { type in
            switch type {
            case .singleSigning:
                self.viewTarget = .singleElementSigning(identity)
            case .bulkSigning:
                self.viewTarget = .bulkSigning(identity)
            }
        })
    }
    
    func singleElementSigningViewModel(identity: KeychainIdentity) -> SingleElementSigningViewModel {
        .init(
            identity: identity,
            completed: {
                self.viewTarget = .certificateSelection
            }
        )
    }
    
    func bulkSigningViewModel(identity: KeychainIdentity) -> BulkSigningViewModel {
        .init(
            identity: identity,
            completed: {
                self.viewTarget = .certificateSelection
            }
        )
    }
}
