/* SafeVault shared lock helper (contains no secrets).
   - Redirects to the lock screen if the server says the session is gone.
   - Provides window.lockVault() for the "Lock Vault" button.
   - Re-checks the session when a page is restored from the back/forward cache. */
(function () {

    var LOCK_URL = "/lock.html";
    var nativeFetch = window.fetch.bind(window);

    function goToLock() {
        window.location.replace(LOCK_URL);
    }

    // Any 401 from a protected API means "locked" -> back to the lock screen.
    window.fetch = function (input, init) {
        return nativeFetch(input, init).then(function (response) {
            var url = typeof input === "string" ? input : (input && input.url) || "";
            if (response.status === 401 &&
                url.indexOf("/api/") !== -1 &&
                url.indexOf("/api/auth/") === -1) {
                goToLock();
            }
            return response;
        });
    };

    window.lockVault = function () {
        return nativeFetch("/api/auth/lock", {
            method: "POST",
            credentials: "same-origin"
        }).catch(function () { /* still leave the page */ })
          .then(goToLock);
    };

    window.addEventListener("pageshow", function (event) {
        if (!event.persisted) return;
        nativeFetch("/api/auth/status", { credentials: "same-origin", cache: "no-store" })
            .then(function (r) { return r.json(); })
            .then(function (d) { if (!d.authenticated) goToLock(); })
            .catch(function () {});
    });

})();
