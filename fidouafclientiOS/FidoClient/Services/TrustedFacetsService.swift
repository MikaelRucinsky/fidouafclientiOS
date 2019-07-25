import Foundation

class TrustedFacetsService {
    
    static private func get(url: String, callback: @escaping ([TrustedFacets]) -> Void) {
        let nsUrl = URL(string: url)
        let session = URLSession.shared
        
        let request = URLRequest(url: nsUrl!)
        
        let task = session.dataTask(with: request, completionHandler: { data, response, error in
            guard error == nil else {
                callback([])
                return
            }
            guard let responseData = data else {
                callback([])
                return
            }
            callback(TrustedFacets.getArrayFromData(data: responseData))
        })
        
        task.resume()
    }
}
