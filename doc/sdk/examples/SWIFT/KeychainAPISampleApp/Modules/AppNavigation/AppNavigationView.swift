//

import SwiftUI

struct AppNavigationView: View {
    private let model = AppNavigationViewModel()
    
    var body: some View {
        switch self.model.viewTarget {
        case .certificateRetrieval:
            CertificateRetrievalView(model: self.model.certificateRetrievalViewModel)
        case .certificateSelection:
            CertificateSelectionView(model: self.model.certificateSelectionViewModel)
        case .signingOperationSelection(let identity):
            SigningOperationSelectionView(model: self.model.signingOperationSelectionViewModel(identity: identity))
        case .singleElementSigning(let identity):
            SingleElementSigningView(model: self.model.singleElementSigningViewModel(identity: identity))
        case .bulkSigning(let identity):
            BulkSigningView(model: self.model.bulkSigningViewModel(identity: identity))
        }
    }
}

#Preview {
    AppNavigationView()
}
