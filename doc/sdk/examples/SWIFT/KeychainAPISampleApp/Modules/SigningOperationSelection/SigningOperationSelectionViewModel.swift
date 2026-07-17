//

import Foundation

class SigningOperationSelectionViewModel {
    // MARK: - Callbacks
    private let operationSelected: (SigningOperationType) -> Void
    
    // MARK: - Lifecycle
    init(operationSelected: @escaping (SigningOperationType) -> Void) {
        self.operationSelected = operationSelected
    }
    
    // MARK: - Actions
    func singleSigningButtonUsed() {
        self.operationSelected(.singleSigning)
    }
    
    func bulkSigningButtonUsed() {
        self.operationSelected(.bulkSigning)
    }
}
