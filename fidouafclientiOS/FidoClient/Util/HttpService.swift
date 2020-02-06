import Foundation

class UrlSessionDelegate: NSObject, URLSessionTaskDelegate {
    func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse, newRequest request: URLRequest, completionHandler: @escaping (URLRequest?) -> Void) {
        if ((response.allHeaderFields["FIDO-AppID-Redirect-Authorized"] as? NSString)?.boolValue ?? false) {
            completionHandler(request)
        } else {
            completionHandler(nil)
        }
    }
}

class HttpService {
    static func getTrustedFacetsFromServer(_ urlString: String, completionHandler: @escaping (TrustedFacetList?) -> Void) {
        
        if (!urlString.starts(with: "https://")) {
            completionHandler(nil)
            return
        }
        
        guard let url = URL(string: urlString) else {
            completionHandler(nil)
            return
        }
        
        print("GetTrustedFacetList from: \(urlString)")
        let config = URLSessionConfiguration.default
        config.requestCachePolicy = .reloadIgnoringLocalCacheData
        config.urlCache = nil
        
        let urlSession = URLSession(configuration: config, delegate: UrlSessionDelegate(), delegateQueue: nil)
        let loadDataTask = urlSession.dataTask(with: url, completionHandler: { dataOption, response, error in
            if let err = error {
                print("HTTPError: \(err)")
            }
            DispatchQueue.main.async {
                if let httpResponse = response as? HTTPURLResponse {
                    if ((200...299).contains(httpResponse.statusCode)) {
                        if let data = dataOption {
                            do {
                                let trustedFacetList = try JSONDecoder().decode(TrustedFacetList.self, from: data)
                                completionHandler(trustedFacetList)
                                return
                            } catch {
                                print("Deserialization of TrustedFacetList failed: \(error)")
                                completionHandler(nil)
                                return
                            }
                        } else {
                            print("No Data for TrustedFacetList transfered")
                            completionHandler(nil)
                            return
                        }
                    } else {
                        print("Get TrustedFacetList was not successful: HTTP-StatusCode: \(httpResponse.statusCode)")
                        completionHandler(nil)
                        return
                    }
                } else {
                    print("Get TrustedFacetList - Response is not an")
                    completionHandler(nil)
                    return
                }
            }
        })
        loadDataTask.resume()
    }
}


