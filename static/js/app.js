document.addEventListener('DOMContentLoaded', function () {
  var toggle = document.querySelector('[data-sidebar-toggle]');
  if (toggle) {
    toggle.addEventListener('click', function () {
      document.body.classList.toggle('sidebar-open');
    });
  }

  document.addEventListener('click', function (event) {
    var sidebar = document.querySelector('.app-sidebar');
    if (!document.body.classList.contains('sidebar-open')) return;
    if (!sidebar) return;
    if (sidebar.contains(event.target) || (toggle && toggle.contains(event.target))) return;
    document.body.classList.remove('sidebar-open');
  });
});
