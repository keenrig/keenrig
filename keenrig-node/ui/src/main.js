import { createApp } from 'vue'
import { createRouter, createWebHashHistory } from 'vue-router'
import { i18n } from './i18n'
import { initTheme } from './theme'
import App from './App.vue'
import LoginView from './views/LoginView.vue'
import AppsView from './views/AppsView.vue'
import AppDetailView from './views/AppDetailView.vue'
import CatalogView from './views/CatalogView.vue'
import DomainsView from './views/DomainsView.vue'
import EventlogView from './views/EventlogView.vue'
import CloudLinkView from './views/CloudLinkView.vue'
import BackupView from './views/BackupView.vue'
import SettingsView from './views/SettingsView.vue'
import './style.css'

// Theme trước khi mount: đặt data-theme sau khi vẽ là một cú nháy trắng → tối.
initTheme()

// Hash history, KHÔNG phải history API: Admin có thể được phục vụ sau một
// reverse proxy ở đường dẫn con, và history API cần server rewrite mọi đường
// dẫn về index.html. Hash chạy đúng ở mọi cấu hình mà không cần server biết gì.
//
// # Bản đồ v2 (design/v2/admin.html): sidebar còn 6 mục
//
// Apps · App Store · Domains · Backups · Cloud Link · Settings. Đường dẫn cũ
// KHÔNG chết — bookmark, link trong tài liệu và thói quen gõ tay vẫn tới đúng
// chỗ qua redirect:
//   /catalog  → /store     (Cài app → App Store)
//   /backup   → /backups
//   /users, /services, /system → /settings (các mục chưa có API giờ được kể
//                                            tên thật thà trong Settings)
// Eventlog có API thật (GET /events) nên giữ nguyên /events, hiện dưới
// Settings › Activity.
const router = createRouter({
  history: createWebHashHistory(),
  routes: [
    { path: '/', redirect: '/apps' },
    { path: '/login', component: LoginView, meta: { public: true } },
    { path: '/apps', component: AppsView, meta: { nav: 'apps' } },
    { path: '/apps/:id', component: AppDetailView, meta: { nav: 'apps' } },
    { path: '/store', component: CatalogView, meta: { nav: 'store' } },
    { path: '/catalog', redirect: (to) => ({ path: '/store', query: to.query }) },
    { path: '/domains', component: DomainsView, meta: { nav: 'domains' } },
    { path: '/backups', component: BackupView, meta: { nav: 'backups' } },
    { path: '/backup', redirect: '/backups' },
    { path: '/cloud', component: CloudLinkView, meta: { nav: 'cloud' } },
    { path: '/settings', component: SettingsView, meta: { nav: 'settings', sub: 'general' } },
    { path: '/events', component: EventlogView, meta: { nav: 'settings', sub: 'events' } },
    { path: '/users', redirect: '/settings' },
    { path: '/services', redirect: '/settings' },
    { path: '/system', redirect: '/settings' },
    { path: '/:pathMatch(.*)*', redirect: '/apps' },
  ],
})

createApp(App).use(router).use(i18n).mount('#app')
