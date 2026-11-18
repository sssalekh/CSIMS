/*
 * Keep the scroll position when a form on the page is submitted.
 *
 * Every action in CSIMS (change severity, update status, add a comment,
 * toggle a rule, ...) submits a form, and the server answers by loading the
 * page again, which normally opens it at the top. Before a form is sent,
 * this script remembers the current page and scroll position. When the same
 * page is loaded again, it returns to that position and shows the result
 * message as a temporary notification, because the original message is
 * displayed at the top of the page.
 */
(function () {
    "use strict";

    const STORAGE_KEY = "csims-scroll-position";
    const NOTIFICATION_TIME = 5000;

    function save(value) {
        try {
            sessionStorage.setItem(STORAGE_KEY, JSON.stringify(value));
        } catch (error) {
            // Storage can be unavailable (for example, in private mode).
        }
    }

    function takeSaved() {
        try {
            const value = JSON.parse(sessionStorage.getItem(STORAGE_KEY));
            sessionStorage.removeItem(STORAGE_KEY);
            return value;
        } catch (error) {
            return null;
        }
    }

    // Bubbling phase: inline confirm() handlers run first, so a cancelled
    // confirmation (defaultPrevented) does not store anything.
    document.addEventListener("submit", function (event) {
        const form = event.target;

        if (event.defaultPrevented) return;
        if ((form.method || "").toLowerCase() !== "post") return;

        save({
            path: window.location.pathname + window.location.search,
            scrollY: window.scrollY
        });
    });

    function showAsNotifications(messages) {
        const container = document.createElement("div");
        container.className = "flash-toast-container";

        messages.forEach(function (message) {
            const toast = message.cloneNode(true);
            toast.classList.add("flash-toast");
            container.appendChild(toast);
        });

        document.body.appendChild(container);

        window.setTimeout(function () {
            container.classList.add("flash-toast-hidden");
            window.setTimeout(function () { container.remove(); }, 400);
        }, NOTIFICATION_TIME);
    }

    window.addEventListener("DOMContentLoaded", function () {
        const saved = takeSaved();
        const currentPath = window.location.pathname + window.location.search;

        if (!saved || saved.path !== currentPath || !saved.scrollY) return;

        window.scrollTo(0, saved.scrollY);

        // Fonts can finish loading after this point and change the page
        // height, so the position is applied once more after full load.
        window.addEventListener("load", function () {
            window.scrollTo(0, saved.scrollY);
        });

        const messages = Array.from(
            document.querySelectorAll(".content-area .flash-message")
        );

        if (messages.length) {
            showAsNotifications(messages);
        }
    });
})();
