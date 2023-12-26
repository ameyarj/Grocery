<template>
  <div>
    <v-row class="mt-10 mb-5">
      <v-col
        cols="12"
        xs="12"
        sm="6"
        md="4"
        v-for="(feedback, index) in feedbacks"
        :key="index"
      >
        <v-card class="elevation-16 mx-auto" width="300">
          <v-list subheader two-line>
            <v-list-item>
              <v-list-item-content>
                <v-list-item-title>{{ feedback.title }}</v-list-item-title>
                <v-list-item-subtitle>{{ feedback.subtitle }}</v-list-item-subtitle>
              </v-list-item-content>
              <v-list-item-avatar align="end" justify="start" size="30" class="ml-2" color="green" style="color: white; display: flex; align-items: center; justify-content: center;">
                <span class="text-h5">{{ feedback.title.charAt(0).toUpperCase() }}</span>
              </v-list-item-avatar>
            </v-list-item>
          </v-list>

          <v-card-text>
            <div class="mt-n7">
              <v-rating
                v-model="feedback.rating"
                color="yellow darken-3"
                background-color="grey darken-1"
                empty-icon="$ratingFull"
                half-increments
                hover
                small
                readonly
              ></v-rating>
            </div>
            {{ feedback.bio }}
          </v-card-text>
        </v-card>
      </v-col>
    </v-row>
    
    <v-btn v-if="showButton" @click="$router.push('/FeedbackForm')">Give Feedback</v-btn>
  </div>
</template>


<script>
export default {
  data: () => ({
    isLoggedIn: localStorage.getItem("token") !== null,
    username: localStorage.getItem("username") || "", 
    role: localStorage.getItem("role") || "",
    feedbacks: [],
  }),
  computed: {
    showButton(){
      const showButton = this.isLoggedIn && this.role !== "admin" && this.role !=="store_manager" ;
      return showButton;
    },
  },
  mounted() {
    fetch('http://localhost:5000/get_feedback')
      .then(response => response.json())
      .then(data => {
        this.feedbacks = data.feedback;
      })
      .catch(error => {
        console.error('Error fetching feedback:', error);
      });
  },
 
};
</script>
