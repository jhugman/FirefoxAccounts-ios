/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

import Foundation
import Account
import Deferred
import Shared
import Sync

import Alamofire
import SwiftyJSON

open class FxASyncClient {
    var tokenServerToken: TokenServerToken
    var keyBundle: KeyBundle
    var keys: Keys?
    var client: Sync15StorageClient


    // NB: static necessary to maintain reference to session manager
    fileprivate static let alamofire: SessionManager = {
        let ua = UserAgent.fxaUserAgent
        let configuration = URLSessionConfiguration.ephemeral
        return SessionManager.managerWithUserAgent(ua, configuration: configuration)
    }()

    public typealias Authorizer = (URLRequest) -> URLRequest
    fileprivate let authorizer: Authorizer

    init(token: TokenServerToken, key: Data) {
        tokenServerToken = token
        keyBundle = KeyBundle.fromKSync(key)

        self.authorizer = {
            (r: URLRequest) -> URLRequest in
            var req = r
            let helper = HawkHelper(id: token.id, key: token.key.data(using: String.Encoding.utf8, allowLossyConversion: false)!)
            req.setValue(helper.getAuthorizationValueFor(r), forHTTPHeaderField: "Authorization")
            return req
        }
        let queue = DispatchQueue.global(qos: DispatchQoS.background.qosClass)
        class MockBackoffStorage: BackoffStorage {
            var serverBackoffUntilLocalTimestamp: Timestamp?

            func clearServerBackoff() {
                serverBackoffUntilLocalTimestamp = nil
            }

            func isInBackoff(_ now: Timestamp) -> Timestamp? {
                return nil
            }
        }
        client = Sync15StorageClient(token: token, workQueue: queue, resultQueue: queue, backoff: MockBackoffStorage())
    }


    fileprivate static func getStorageEndpoint(server: String, collection: String) -> URL? {
        return URL(string: server + "/" + collection)
    }


    func fetchKeys() {
//        self.client.getCryptoKeys(keyBundle, ifUnmodifiedSince: nil).upon { result in
//            if let resp = result.successValue {
//                self.keys = Keys(payload: resp.value.payload)
//            }
//        }
    }

    public func getHistory() {
        fetchKeys()
        /*
        if let url = FxASyncClient.getStorageEndpoint(server: self.tokenServerToken.api_endpoint, collection: "storage/history?full=1&limit=4") {
            var req = URLRequest(url: url as URL)
            req.httpMethod = URLRequest.Method.get.rawValue
            req.setValue("application/json", forHTTPHeaderField: "Accept")
            let authorized: URLRequest = self.authorizer(req)

            let request = FxASyncClient.alamofire.request(authorized)
                .validate(contentType: ["application/json"]) as DataRequest

            request.responsePartialParsedJSON({ (response: DataResponse<JSON>) in
                // TODO: extract and decrypt history from response
                print(response.data)
                if let dataJSON: JSON = response.result.value {
                    print(dataJSON)
                    for item in dataJSON.array! {
                        print(item)
                        let payloadJSON = JSON(parseJSON: item["payload"].string!)
                    print(payloadJSON["ciphertext"])
                    let ciphertext = Bytes.decodeBase64(payloadJSON["ciphertext"].stringValue)
                    let iv = Bytes.decodeBase64(payloadJSON["IV"].stringValue)
                    print(ciphertext)
                    print(iv)
                    let decrypted = self.keyBundle.decrypt(ciphertext!, iv: iv!)
                    print(decrypted)
                    }
                }


            })
        }
 */
    }
}
