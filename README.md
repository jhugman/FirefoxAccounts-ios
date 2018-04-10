## lockbox-ios-fxa-sync

This is intended to be the FxA/Sync library pulled out of [Firefox for iOS][1] for use in [Lockbox iOS][2].

The intent is that this will be useful: 

 * to ship a v1.0 of lockbox
 * to define the APIs for [whatever comes next][3]
 * to be easily discarded when whatever comes next, comes next.

It is a fairly mechanical extraction, with a focus on making passwords/logins work, and changing as little code as possible.

Additionally, this is fairly early on in the project lifecycle.

As such, quite a lot of naming is not yet nailed down.

### Building

`lockbox-ios-fxa-sync` requires [carthage][carthage].

The simplest route to getting this is via `brew` package manager.

```sh
brew update
brew install carthage
```

Once you have used the package manager to get the package manager, you can use it to manage the packages.

Finish setup with:

```sh
./bootstrap.sh

# Opens Xcode.
open fxa-ios.xcodeproj
```

### Running the demo app

Run the target `fxa-ios` on a simulator.

 * Hit `Login`
 * Login with some Firefox for iOS credentials
 * Watch for the yellow messages at the bottom of the screen.
 * Hit `Logout`.

The messages in the demo app are the sync status.

### Importing with Carthage. 

TBD.

## License

`lockbox-ios-fxa-sync` is currently licensed under the Apache License v2.0. See the [LICENSE][LICENSE] file for details.

[1]: https://github.com/mozilla-mobile/firefox-ios
[2]: https://github.com/mozilla-lockbox/lockbox-ios
[3]: https://github.com/mozilla/mentat
[carthage]: https://github.com/Carthage/Carthage
[LICENSE]: LICENSE