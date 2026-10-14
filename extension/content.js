// URL Shield content script.
// Guards sensitive browser permissions (camera, microphone, location,
// notifications) so that untrusted sites cannot access them. It asks the
// background worker whether the current host is trusted; if not, the
// permission request is blocked and the user is warned.
//
// Runs at document_start so the overrides are in place before page scripts
// can call these APIs.

(function () {
  'use strict';

  // Ask the background worker if this host is trusted (verdict SAFE).
  // Fail-closed: if we can't get an answer, treat the site as untrusted.
  function isTrusted() {
    return new Promise((resolve) => {
      try {
        chrome.runtime.sendMessage(
          { type: 'URLSHIELD_IS_TRUSTED', url: location.href },
          (resp) => {
            if (chrome.runtime.lastError || !resp) {
              resolve(false);
              return;
            }
            resolve(!!resp.trusted);
          }
        );
      } catch (e) {
        resolve(false);
      }
    });
  }

  function warn(feature) {
    console.warn(
      '[URL Shield] Blocked "' + feature + '" on an untrusted site. ' +
      'This permission is only allowed on sites verified safe.'
    );
  }

  function blockedError(feature) {
    return new DOMException(
      'URL Shield blocked ' + feature + ' on this untrusted site.',
      'NotAllowedError'
    );
  }

  // --- getUserMedia (camera / microphone) ---
  if (navigator.mediaDevices && navigator.mediaDevices.getUserMedia) {
    const realGUM = navigator.mediaDevices.getUserMedia.bind(
      navigator.mediaDevices
    );
    navigator.mediaDevices.getUserMedia = async function (constraints) {
      if (await isTrusted()) {
        return realGUM(constraints);
      }
      warn('camera/microphone');
      throw blockedError('camera/microphone access');
    };
  }

  // Legacy getUserMedia aliases.
  ['getUserMedia', 'webkitGetUserMedia', 'mozGetUserMedia'].forEach((name) => {
    if (typeof navigator[name] === 'function') {
      const real = navigator[name].bind(navigator);
      navigator[name] = function (constraints, success, failure) {
        isTrusted().then((ok) => {
          if (ok) {
            real(constraints, success, failure);
          } else {
            warn('camera/microphone');
            if (failure) {
              failure(blockedError('camera/microphone access'));
            }
          }
        });
      };
    }
  });

  // --- Geolocation ---
  if (navigator.geolocation) {
    const geo = navigator.geolocation;
    const realCurrent = geo.getCurrentPosition.bind(geo);
    const realWatch = geo.watchPosition.bind(geo);

    geo.getCurrentPosition = function (success, error, options) {
      isTrusted().then((ok) => {
        if (ok) {
          realCurrent(success, error, options);
        } else {
          warn('location');
          if (error) {
            error({ code: 1, message: 'URL Shield blocked location access.' });
          }
        }
      });
    };

    geo.watchPosition = function (success, error, options) {
      isTrusted().then((ok) => {
        if (ok) {
          realWatch(success, error, options);
        } else {
          warn('location');
          if (error) {
            error({ code: 1, message: 'URL Shield blocked location access.' });
          }
        }
      });
      return -1; // a watch id that never fires
    };
  }

  // --- Notifications ---
  if (window.Notification && Notification.requestPermission) {
    const realRequest = Notification.requestPermission.bind(Notification);
    Notification.requestPermission = function (cb) {
      return isTrusted().then((ok) => {
        if (ok) {
          return realRequest(cb);
        }
        warn('notifications');
        if (cb) {
          cb('denied');
        }
        return 'denied';
      });
    };
  }
})();
