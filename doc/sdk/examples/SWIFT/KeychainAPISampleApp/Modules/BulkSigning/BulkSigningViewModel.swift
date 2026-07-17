//

import Foundation
import Cocoa

@Observable
class BulkSigningViewModel {
    // MARK: - Observable properties
    private(set) var viewState: BulkSigningViewState = .filesSelection
    var showFileImporter = false
    
    // MARK: - Internal properties
    private let identity: KeychainIdentity
    private let completed: () -> Void
    
    // MARK: - Lifecycle
    init(
        identity: KeychainIdentity,
        completed: @escaping () -> Void
    ) {
        self.identity = identity
        self.completed = completed
    }
    
    // MARK: - Actions
    func selectFilesButtonUsed() {
        self.showFileImporter = true
    }
    
    func filesSelected(_ urls: [URL]) {
        self.viewState = .waitingForSignature
        self.startBulkSignature(for: urls)
    }
    
    func backButtonUsed() {
        self.completed()
    }
    
    func urlOpened(_ url: URL) {
        guard url.host() == "bulk-signed-result",
              let queryItems = URLComponents(string: url.absoluteString),
              let value = queryItems.queryItems?.first(where: { $0.name == "signature" })?.value,
              let signatureData = Data(base64Encoded: value)
        else {
            self.viewState = .error("Wrong callback received: \(url)")
            return
        }
        
        self.viewState = .signatureCompleted(signatureData.hexEncodedString)
    }
    
    // MARK: - Internals
    private func startBulkSignature(for urls: [URL]) {
        let tokenId = self.identity.privateKey.tokenId ?? ""
        let request = BulkSigningRequest(tokenId: tokenId, urls: urls)
        let streamedRequest = (try? JSONEncoder().encode(request)) ?? Data()
        let deeplink = "beidsign://bulk?request=\(streamedRequest.base64EncodedString())&callback=keychainsample://bulk-signed-result"
        NSWorkspace.shared.open(URL(string: deeplink)!)
    }
}
