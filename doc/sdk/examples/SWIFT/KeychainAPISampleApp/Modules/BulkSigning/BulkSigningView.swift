//

import SwiftUI
import UniformTypeIdentifiers

struct BulkSigningView: View {
    @Bindable private var model: BulkSigningViewModel
    
    init(model: BulkSigningViewModel) {
        self.model = model
    }
    
    var body: some View {
        VStack(spacing: 20) {
            switch self.model.viewState {
            case .filesSelection:
                Button("Select files for bulk signing") {
                    self.model.selectFilesButtonUsed()
                }
                .buttonStyle(.borderedProminent)
            case .waitingForSignature:
                Text("Waiting for signature...")
                ProgressView()
            case .signatureCompleted(let signatureHex):
                Text("Signature completed! Hex value below.")
                Text(signatureHex)
                Button("Back") {
                    self.model.backButtonUsed()
                }
                .buttonStyle(.borderedProminent)
            case .error(let errorText):
                Text("Signature failed: \(errorText)")
                Button("Back") {
                    self.model.backButtonUsed()
                }
                .buttonStyle(.borderedProminent)
            }
        }
        .fileImporter(
            isPresented: self.$model.showFileImporter,
            allowedContentTypes: [.data],
            allowsMultipleSelection: true
        ) { result in
            switch result {
            case .success(let urls):
                self.model.filesSelected(urls)
            case .failure:
                break
            }
        }
        .onOpenURL { url in
            self.model.urlOpened(url)
        }
    }
}
