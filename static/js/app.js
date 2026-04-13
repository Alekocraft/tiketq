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

  var markReadBtn = document.getElementById('markReadBtn');
  if (markReadBtn) {
    markReadBtn.addEventListener('click', function () {
      if (markReadBtn.disabled) return;

      var statusLabel = document.getElementById('markReadStatus');
      markReadBtn.disabled = true;
      if (statusLabel) {
        statusLabel.textContent = 'Actualizando notificaciones...';
      }

      fetch('/notifications/mark-read', {
        method: 'POST',
        headers: {
          'X-Requested-With': 'XMLHttpRequest'
        }
      })
        .then(function (response) {
          if (!response.ok) throw new Error('request_failed');
          return response.json();
        })
        .then(function (payload) {
          var affected = Number(payload && payload.affected ? payload.affected : 0);

          document.querySelectorAll('.notification-card--unread').forEach(function (card) {
            card.classList.remove('notification-card--unread');
            card.classList.add('notification-card--read');
            var state = card.querySelector('.notification-state');
            if (state) {
              state.classList.remove('notification-state--new');
              state.textContent = 'Leída';
            }
          });

          document.querySelectorAll('[data-notif-count-badge]').forEach(function (badge) {
            badge.textContent = '0';
            badge.classList.add('is-hidden');
          });

          var bell = document.querySelector('.notif-bell');
          if (bell) {
            bell.classList.remove('notif-bell--active');
            bell.setAttribute('data-state', 'empty');
          }

          var unreadValue = document.querySelector('[data-summary-unread]');
          var readValue = document.querySelector('[data-summary-read]');
          var totalValue = document.querySelector('[data-summary-total]');
          if (unreadValue) unreadValue.textContent = '0';
          if (readValue && totalValue) {
            readValue.textContent = totalValue.textContent;
          }

          if (statusLabel) {
            statusLabel.textContent = affected > 0 ? 'Todas las notificaciones quedaron marcadas como leídas.' : 'No había notificaciones pendientes por marcar.';
          }
        })
        .catch(function () {
          if (statusLabel) {
            statusLabel.textContent = 'No fue posible actualizar las notificaciones. Intenta nuevamente.';
          }
          markReadBtn.disabled = false;
        })
        .finally(function () {
          if (statusLabel && statusLabel.textContent.indexOf('No fue posible') === -1) {
            markReadBtn.disabled = true;
          }
        });
    });
  }
});
