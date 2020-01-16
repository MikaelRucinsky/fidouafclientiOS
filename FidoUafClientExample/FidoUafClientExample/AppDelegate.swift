import UIKit
import FidoUafClientiOS

public let kNotification = Notification.Name("kNotification")

@UIApplicationMain
class AppDelegate: UIResponder, UIApplicationDelegate {

    func application(_ application: UIApplication, didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]?) -> Bool {
        // Override point for customization after application launch.
        NSLog("LaunchOptions: \(launchOptions)")
        return true
    }

    // MARK: UISceneSession Lifecycle

    func application(_ application: UIApplication, configurationForConnecting connectingSceneSession: UISceneSession, options: UIScene.ConnectionOptions) -> UISceneConfiguration {
        // Called when a new scene session is being created.
        // Use this method to select a configuration to create the new scene with.
        return UISceneConfiguration(name: "Default Configuration", sessionRole: connectingSceneSession.role)
    }

    func application(_ application: UIApplication, didDiscardSceneSessions sceneSessions: Set<UISceneSession>) {
        // Called when the user discards a scene session.
        // If any sessions were discarded while the application was not running, this will be called shortly after application:didFinishLaunchingWithOptions.
        // Use this method to release any resources that were specific to the discarded scenes, as they will not return.
    }
    
    func applicationDidBecomeActive(_ application: UIApplication) {
        NSLog("applicationDidBecomeActive")
    }
    
    func applicationWillEnterForeground(_ application: UIApplication) {
        NSLog("applicationWillEnterForeground")
    }

    func application(_ application: UIApplication, handleOpen url: URL) -> Bool {
        NSLog("URL: \(url)")
        NSLog("URL.scheme: \(url.scheme)")
        NSLog("URL.host: \(url.host)")
        NSLog("URL.path: \(url.path)")
        NSLog("URL.query: \(url.query)")
        NSLog("URL.fragment: \(url.fragment)")
        NSLog("URL.pathComponents: \(url.pathComponents)")
        
        return true
    }
    
    func application(_ application: UIApplication, open url: URL, sourceApplication: String?, annotation: Any) -> Bool {
        let urlDict: [String: URL] = ["url": url]
        
        NotificationCenter.default.post(name: kNotification, object: nil, userInfo: urlDict)
        
        NSLog("SourceApplication: \(sourceApplication)")
        
        NSLog("URL: \(url)")
        NSLog("URL.scheme: \(url.scheme)")
        NSLog("URL.host: \(url.host)")
        NSLog("URL.path: \(url.path)")
        NSLog("URL.query: \(url.query)")
        NSLog("URL.fragment: \(url.fragment)")
        NSLog("URL.pathComponents: \(url.pathComponents)")
        
        return true
    }
    
    func application(_ app: UIApplication, open url: URL, options: [UIApplication.OpenURLOptionsKey : Any] = [:]) -> Bool {
        
        let urlDict: [String: URL] = ["url": url]
        
        NotificationCenter.default.post(name: kNotification, object: nil, userInfo: urlDict)
        
        UIApplication.shared.applicationIconBadgeNumber = 11
        
        NSLog("SourceApplication: \(options[UIApplication.OpenURLOptionsKey.sourceApplication])")
        
        NSLog("URL: \(url)")
        NSLog("URL.scheme: \(url.scheme)")
        NSLog("URL.host: \(url.host)")
        NSLog("URL.path: \(url.path)")
        NSLog("URL.query: \(url.query)")
        NSLog("URL.fragment: \(url.fragment)")
        NSLog("URL.pathComponents: \(url.pathComponents)")
        
        return true
    }
    
    // MARK: X-Callback-URL actions
    
    func discoverAction() {
        
    }
    
    func checkPolicyAction() {
//        FidoClient.
    }
    
    func uafOperationAction() {
//        FidoClient.process(uafMessage: )
    }

}

