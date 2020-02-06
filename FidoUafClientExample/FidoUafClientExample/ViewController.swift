import UIKit
import FidoUafClientiOS
import CallbackURLKit

class ViewController: UIViewController {
    
    // MARK: PROPERTIES
    @IBOutlet weak var labelErrorCode: UILabel!
    @IBOutlet weak var labelResult: UILabel!
    
    
    private let registrationRequest = "[{\"header\":{\"upv\":{\"major\":1,\"minor\":1},\"op\":\"Reg\",\"appID\":\"\"},\"challenge\":\"H9iW9yA9aAXF_lelQoi_DhUk514Ad8Tqv0zCnCqKDpo\",\"username\":\"hello@test.com\",\"policy\":{\"accepted\":[[{\"aaid\":[\"006F#0002\"]}]]}}]"
    private let authenticationRequest = "[{\"header\":{\"upv\":{\"major\":1,\"minor\":1},\"op\":\"Auth\",\"appID\":\"\"},\"challenge\":\"HQ1VkTUQC1NJDOo6OOWdxewrb9i5WthjfKIehFxpeuU\",\"policy\":{\"accepted\":[[{\"aaid\":[\"006F#0002\"]}]]}}]"
    private let deregistrationRequest = "[{\"header\":{\"op\":\"Dereg\",\"upv\":{\"major\":1,\"minor\":1},\"appID\":\"\"},\"authenticators\":[{\"aaid\":\"006F#0002\",\"keyID\":\"\"}]}]"
    
    override func viewDidLoad() {
        super.viewDidLoad()
        // Do any additional setup after loading the view.
    }

    // MARK: Actions
    @IBAction func register(_ sender: UIButton) {
        FidoClient.process(uafMessage: UAFMessage(uafProtocolMessage: registrationRequest), skipTrustedFacetVerification: true) { resultMessage, error in
            self.showResult(resultMessage: resultMessage, error: error)
        }
    }
    
    @IBAction func authenticate(_ sender: UIButton) {
        FidoClient.process(uafMessage: UAFMessage(uafProtocolMessage: authenticationRequest)) { resultMessage, error in
            self.showResult(resultMessage: resultMessage, error: error)
        }
    }
    
    @IBAction func deregister(_ sender: UIButton) {
        FidoClient.process(uafMessage: UAFMessage(uafProtocolMessage: deregistrationRequest)) { resultMessage, error in
            self.showResult(resultMessage: resultMessage, error: error)
        }
    }
    
    private func showResult(resultMessage: UAFMessage?, error: FidoError) {
        self.labelErrorCode.text = "\(error)"
        if let message = resultMessage {
            if let encodedMessage = try? JSONEncoder().encode(message) {
                self.labelResult.text = String(data: encodedMessage, encoding: .utf8)
            }
        }
    }
}

