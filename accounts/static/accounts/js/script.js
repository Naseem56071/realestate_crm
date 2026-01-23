const sidebar = document.getElementById("sidebar");
const openBtn = document.getElementById("openSidebar");
const closeBtn = document.getElementById("closeSidebar");

openBtn.addEventListener("click", () => {
    sidebar.classList.add("show");
});

closeBtn.addEventListener("click", () => {
    sidebar.classList.remove("show");
});

setTimeout(function () {
    document.querySelectorAll('.auto-dismiss').forEach(function (alert) {
        let bsAlert = new bootstrap.Alert(alert);
        bsAlert.close();
    });
}, 5000); // 5 seconds

