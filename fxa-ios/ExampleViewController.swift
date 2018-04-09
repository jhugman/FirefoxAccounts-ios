/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

import Foundation
import UIKit
import FxAUtils
import Shared

class ExampleViewController: UIViewController {
    lazy var textButton: UIButton = {
        let button = UIButton()
        return button
    }()

    lazy var statusText: UILabel = {
        let label = UILabel()

        label.textColor = .yellow
        label.font = UIFont.systemFont(ofSize: UIFont.systemFontSize)
        label.textAlignment = .center
        label.numberOfLines = 1

        return label
    }()

    weak var profile: Profile?

    var observers: [NSObjectProtocol]!

    init() {
        super.init(nibName: nil, bundle: nil)
    }

    required init?(coder aDecoder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }

    override func viewDidLoad() {
        super.viewDidLoad()

        guard let delegate = UIApplication.shared.delegate as? AppDelegate,
            let profile = delegate.profile else {
                fatalError()
        }

        self.profile = profile

        view.backgroundColor = UIColor.gray

        view.addSubview(textButton)
        view.addSubview(statusText)

        let buttonConstraints = [
            textButton.leadingAnchor.constraint(equalTo: view.leadingAnchor),
            textButton.trailingAnchor.constraint(equalTo: view.trailingAnchor),
            textButton.topAnchor.constraint(equalTo: self.topLayoutGuide.bottomAnchor),
            textButton.bottomAnchor.constraint(equalTo: self.bottomLayoutGuide.topAnchor),
        ]

        let labelConstraints = [
            statusText.leadingAnchor.constraint(equalTo: view.leadingAnchor),
            statusText.trailingAnchor.constraint(equalTo: view.trailingAnchor),
            statusText.topAnchor.constraint(equalTo: textButton.bottomAnchor, constant: 5),
        ]

        NSLayoutConstraint.activate(buttonConstraints, translatesAutoresizingMaskIntoConstraints: false)
        NSLayoutConstraint.activate(labelConstraints, translatesAutoresizingMaskIntoConstraints: false)

        let names: [Notification.Name] = [.FirefoxAccountVerified, .ProfileDidStartSyncing, .ProfileDidFinishSyncing]
        observers = names.map { name in
            return NotificationCenter.default.addObserver(forName: name, object: nil, queue: .main, using: updateLabel(_:))
        }

        prepareButton()
    }

    deinit {
        observers.forEach { observer in
            NotificationCenter.default.removeObserver(observer)
        }
    }

    func updateLabel(_ notification: Notification) {
        if let appDelegate = UIApplication.shared.delegate as? AppDelegate,
            let profile = appDelegate.profile ,
            let status = profile.syncManager.syncDisplayState {
            statusText.text = "\(notification.name.rawValue): \(status)"
        } else {
            statusText.text = "\(notification.name.rawValue): unknown sync status"
        }

        self.prepareButton()
    }
}

extension ExampleViewController {
    func prepareButton() {
        guard let profile = profile else {
            statusText.text = "Error"
            return
        }

        if profile.hasAccount() {
            showLogoutButton()
        } else {
            showLoginButton()
        }
    }

    func loginPressed() {
        guard let profile = self.profile else {
            return
        }

        let url = profile.accountConfiguration.signInURL
        let fxaViewController = FxAViewController(signInURL: url)
        self.present(fxaViewController, animated: true) {
            guard profile.hasAccount() else {
                self.statusText.text = "No account"
                return
            }

            self.prepareButton()
        }
    }

    func showLogoutButton() {
        let button = self.textButton
        button.setTitle("Logout", for: .normal)
        button.removeTarget(self, action: #selector(self.loginPressed), for: .touchUpInside)
        button.addTarget(self, action: #selector(self.logoutPressed), for: .touchUpInside)
    }

    func showLoginButton() {
        let button = self.textButton
        button.setTitle("Login", for: .normal)
        button.removeTarget(self, action: #selector(logoutPressed), for: .touchUpInside)
        button.addTarget(self, action: #selector(loginPressed), for: .touchUpInside)

        statusText.text = "No account"
    }

    func logoutPressed() {
        FxALoginHelper.sharedInstance.applicationDidDisconnect(UIApplication.shared)

        prepareButton()
    }
}
