import Vue from 'vue'
import VueRouter from 'vue-router'
import HomeView from '../views/HomeView.vue'
import UserLogin from '../components/UserLogin.vue'
import UserSignup from '../components/UserSignup.vue'
import AdminLogin from '../components/AdminLogin.vue';
import AdminDash from '../components/AdminDash.vue';
import SmanagerSignup from '../components/SmanagerSignup.vue';
import SmanagerDash from '../components/SmanagerDash.vue';
import AdminMain from '../components/AdminMain.vue';
import SmanagerLogin from '../components/SmanagerLogin.vue';
import AddCategory from '../components/AddCategory.vue';
import EditCategory from '../components/EditCategory.vue';
import AddProduct from '../components/AddProduct.vue';
import EditProduct from '../components/EditProduct.vue';
import SearchResult from '../components/SearchResult.vue';
import CartDialog from '../components/CartDialog.vue';
import CategoryProduct from '../components/CategoryProduct.vue';
import PurchaseHistory from '../components/PurchaseHistory.vue';
import UserSettings from '../components/UserSettings.vue';
import FeedbackForm from '../components/FeedbackForm.vue'
Vue.use(VueRouter)

const routes = [
  {
    path: '/',
    name: 'home',
    component: HomeView
  },
  {
    path: '/UserLogin',
    component: UserLogin
  },
  {
    path: '/UserSignup',
    component: UserSignup
  },
  {
    path: '/AdminLogin',
    component: AdminLogin
  },
  {
    path: '/AdminDash',
    name: 'AdminDash',
    component: AdminDash
  },
  {
    path: '/AdminMain',
    name: 'AdminMain',
    component: AdminMain
  },
  {
    path: '/SmanagerSignup',
    component: SmanagerSignup
  },
  {
    path: '/SmanagerDash',
    name: 'SmanagerDash',
    component: SmanagerDash
  },
  {
    path: '/SmanagerLogin',
    name: 'SmanagerLogin',
    component: SmanagerLogin
  },
  {
    path: '/AddCategory',
    name: 'AddCategory',
    component: AddCategory
  },
  {
    path: '/EditCategory',
    name: 'EditCategory',
    component: EditCategory
  },
  {
    path: '/AddProduct',
    name: 'AddProduct',
    component: AddProduct
  },
  {
    path: '/EditProduct',
    name: 'EditProduct',
    component: EditProduct
  },
  {
    path: '/SearchResult',
    name: 'SearchResult',
    component: SearchResult
  },
  {
    path: '/CartDialog',
    name: 'CartDialog',
    component: CartDialog
  },
  {
    path: '/CategoryProduct',
    name: 'CategoryProduct',
    component: CategoryProduct
  },
  {
    path: '/PurchaseHistory',
    name: 'PurchaseHistory',
    component: PurchaseHistory
  },
  {
    path: '/UserSettings',
    name: 'UserSettings',
    component: UserSettings
  },
  {
    path: '/FeedbackForm',
    name: 'FeedbackForm',
    component: FeedbackForm
  },
  

]

const router = new VueRouter({
  mode: 'history',
  base: process.env.BASE_URL,
  routes
})

export default router
