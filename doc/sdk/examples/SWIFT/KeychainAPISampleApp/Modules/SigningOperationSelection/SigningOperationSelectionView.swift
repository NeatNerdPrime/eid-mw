//

import SwiftUI

struct SigningOperationSelectionView: View {
    private let model: SigningOperationSelectionViewModel
    
    init(model: SigningOperationSelectionViewModel) {
        self.model = model
    }
    
    var body: some View {
        VStack(spacing: 20) {
            Button("Sign single element") {
                self.model.singleSigningButtonUsed()
            }
            Button("Sign multiple documents") {
                self.model.bulkSigningButtonUsed()
            }
        }
        .buttonStyle(.borderedProminent)
    }
}

#Preview {
    SigningOperationSelectionView(model: .init(operationSelected: { _ in }))
}
