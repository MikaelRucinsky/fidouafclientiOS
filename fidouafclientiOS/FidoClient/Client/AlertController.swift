import UIKit

class AlertController: UIAlertController {
    var alertWindow: UIWindow? = nil
    
    func show(animated flag: Bool = true, completion: (() -> Void)? = nil) {
        alertWindow = UIWindow(frame: UIScreen.main.bounds)
        alertWindow?.rootViewController = ClearViewController()
        alertWindow?.backgroundColor = UIColor.clear
        alertWindow?.windowLevel = UIWindow.Level.alert
        
        if let rootViewController = alertWindow?.rootViewController {
            alertWindow?.makeKeyAndVisible()
            
            rootViewController.present(self, animated: flag, completion: completion)
        }
    }
}

private class ClearViewController: UIViewController {
    override var preferredStatusBarStyle: UIStatusBarStyle {
        return UIApplication.shared.statusBarStyle
    }
    
    override var prefersStatusBarHidden: Bool {
        return UIApplication.shared.isStatusBarHidden
    }
}
