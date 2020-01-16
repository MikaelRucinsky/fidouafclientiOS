import UIKit
import FidoUafClientiOS
import CallbackURLKit

class ViewController: UIViewController {
    
    // MARK: PROPERTIES
    @IBOutlet weak var labelErrorCode: UILabel!
    @IBOutlet weak var labelResult: UILabel!
    
    override func viewDidLoad() {
        super.viewDidLoad()
        // Do any additional setup after loading the view.
        
        NotificationCenter.default.addObserver(self, selector: #selector(self.showUrl(_:)), name: kNotification, object: nil)
    }
    
    @objc func showUrl(_ notification: NSNotification) {
        if let url = notification.userInfo?["url"] as? URL {
            labelResult.text = url.absoluteString
        }
    }

    // MARK: Actions
    @IBAction func register(_ sender: UIButton) {
        
    }
    
    @IBAction func authenticate(_ sender: UIButton) {
        
    }
    
    @IBAction func deregister(_ sender: UIButton) {
        
    }
}

