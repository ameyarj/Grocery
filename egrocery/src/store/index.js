import Vue from 'vue'
import Vuex from 'vuex'

Vue.use(Vuex)

export default new Vuex.Store({
  state: {
    user: null,
    token: null,
  },
  getters: {
    isLoggedIn(state) {
      return !!state.token;
    }
  },
  mutations: {
    setToken(state, token) {
      state.token = token;
      localStorage.setItem('authToken', token);
    },
    setUser(state, user) {
      state.user = user;
    },
    clearToken(state) {
      state.token = null;
      localStorage.removeItem('authToken');
    },
  },
  })
