import axios from 'axios'

const API = axios.create({
  baseURL: 'http://localhost:5000/api'
})

<<<<<<< HEAD
=======
// Attach JWT token to every request
>>>>>>> feature/backend
API.interceptors.request.use((config) => {
  const token = localStorage.getItem('token')
  if (token) {
    config.headers.Authorization = `Bearer ${token}`
  }
  return config
})

<<<<<<< HEAD
export default API
=======
export default API
>>>>>>> feature/backend
