<template>
    <div>
      <Navbar />
      <div class="feedback-form-container">
        <h1>Provide Feedback</h1>
        <form @submit.prevent="submitFeedback" class="feedback-form">
          <div class="form-group">
            <label for="title">Title:</label>
            <input type="text" id="title" v-model="feedback.title" required class="outlined-input">
          </div>
  
          <div class="form-group">
            <label for="subtitle">Subtitle:</label>
            <input type="text" id="subtitle" v-model="feedback.subtitle" class="outlined-input">
          </div>
  
          <div class="form-group">
            <label for="bio">Bio:</label>
            <textarea id="bio" v-model="feedback.bio" required class="outlined-input"></textarea>
          </div>
  
          <div class="form-group">
            <label for="rating">Rating:</label>
            <v-rating
              v-model="feedback.rating"
              color="yellow darken-3"
              background-color="grey darken-1"
              empty-icon="$ratingFull"
              half-increments
              hover
              small
            ></v-rating>
          </div>
  
          <button type="submit" class="submit-btn">Submit Feedback</button>
        </form>
      </div>
    </div>
  </template>
  
  <script>
  import Navbar from '../components/NavbarComponent.vue'
  export default {
    data() {
      return {
        feedback: {
          title: '',
          subtitle: '',
          bio: '',
          rating: 0,
        },
      };
    },
    components:{
      Navbar,
    },
    methods: {
      submitFeedback() {
        const token = localStorage.getItem("token");
  
        fetch("http://localhost:5000/submit_feedback", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "Authorization": `Bearer ${token}`,
          },
          body: JSON.stringify(this.feedback),
        })
          .then(async (response) => {
            if (response.ok) {
              console.log(response);
              this.$router.push('/');
            } else {
              const data = await response.json();
              console.error('Error submitting feedback:', data);
            }
          })
          .catch((error) => {
            console.error('Error submitting feedback:', error);
          });
      },
    },
  };
  </script>
  
  <style scoped>
  .feedback-form-container {
    max-width: 400px;
    margin: auto;
    padding: 20px;
    border: 1px solid #ccc;
    border-radius: 8px;
    box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
  }
  
  .feedback-form {
    display: flex;
    flex-direction: column;
  }
  
  .form-group {
    margin-bottom: 15px;
  }
  
  label {
    font-weight: bold;
  }
  
  textarea {
    min-height: 100px;
  }
  
  .outlined-input {
    border: 1px solid green;
    border-radius: 5px;
    padding: 8px;
    box-sizing: border-box;
    width: 100%;
    margin-top: 5px; /* Add some space between input fields */
  }
  
  .submit-btn {
    background-color: #4caf50;
    color: white;
    padding: 10px;
    border: none;
    border-radius: 5px;
    cursor: pointer;
  }
  
  .submit-btn:hover {
    background-color: #45a049;
  }
  </style>
  