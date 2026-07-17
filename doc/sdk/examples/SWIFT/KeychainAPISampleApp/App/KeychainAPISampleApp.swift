//

import SwiftUI

@main
struct KeychainAPISampleApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) var appDelegate
    
    var body: some Scene {
        WindowGroup {
            AppNavigationView()
                .padding()
                .handlesExternalEvents(preferring: ["*"], allowing: ["*"])
        }
    }
}

class AppDelegate: NSObject, NSApplicationDelegate {
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        true
    }
}
