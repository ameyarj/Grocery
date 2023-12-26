<template>
    <div>
    <Navbar />
      <h1>User Settings</h1>
      <v-card>
        <v-card-title>Current User Details</v-card-title>
        <v-card-text>
          <v-list>
            <v-list-item v-for="detail in userDetails" :key="detail.label">
              <v-list-item-content>
                <v-list-item-title>{{ detail.label }}:</v-list-item-title>
                <v-list-item-subtitle v-if="!isEditing">{{ detail.value }}</v-list-item-subtitle>
                <v-text-field
                  v-else
                  v-model="detail.value"
                  :label="`New ${detail.label}`"
                ></v-text-field>
              </v-list-item-content>
            </v-list-item>
          </v-list>
        </v-card-text>
        <v-card-actions>
          <v-btn v-if="!isEditing" @click="startEditing">Edit</v-btn>
        </v-card-actions>
      </v-card>
  
      <v-form v-if="isEditing" @submit.prevent="saveChanges">
        <!-- You can add more fields here if needed -->
        <v-text-field v-model="newPassword" label="New Password" type="password"></v-text-field>
        <v-btn v-if="isEditing" @click="cancelEditing">Cancel</v-btn>
        <v-btn color="green" type="submit">Save Changes</v-btn>
      </v-form>
    </div>
  </template>
  
  <script>
  import Navbar from "../components/NavbarComponent";
  export default {
    data() {
      return {
        userDetails: [
          { label: 'Username', value: '' },
          { label: 'Email', value: '' },
          // You can add more details here
        ],
        newPassword: '',
        isEditing: false,
      };
    },
    components: {
        Navbar,
    },
    created() {
      this.fetchUserDetails();
    },
    methods: {
      fetchUserDetails() {
        fetch('http://localhost:5000/user/details', {
          method: 'GET',
          headers: {
            'Authorization': `Bearer ${localStorage.getItem('token')}`,
          },
        })
          .then(async (response) => {
            if (response.ok) {
              const data = await response.json();
              this.userDetails.forEach((detail) => {
                detail.value = data[detail.label.toLowerCase()];
              });
            } else {
              console.error('Failed to fetch user details:', response.status);
            }
          })
          .catch((error) => {
            console.error('An unexpected error occurred:', error);
          });
      },
      startEditing() {
        this.isEditing = true;
      },
      cancelEditing() {
        this.isEditing = false;
        this.newPassword = '';
        this.fetchUserDetails();
      },
      saveChanges() {
        const data = {
            new_username: this.userDetails.find((detail) => detail.label === 'Username').value,
            new_email: this.userDetails.find((detail) => detail.label === 'Email').value,
            new_password: this.newPassword,
        };

        fetch('http://localhost:5000/user/edit', {
            method: 'PUT',
            headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${localStorage.getItem('token')}`,
            },
            body: JSON.stringify(data),
        })
            .then(async (response) => {
            if (response.ok) {
                const responseData = await response.json();
                const newToken = responseData.token;
                console.log("New Token from Backend:", newToken);

                // Replace the old token in local storage with the new one
                localStorage.setItem('token', newToken);

                console.log('User details updated successfully');
                
                this.userDetails.find((detail) => detail.label === 'Username').value = data.new_username;
                this.userDetails.find((detail) => detail.label === 'Email').value = data.new_email;

                this.isEditing = false;
                this.newPassword = '';
            } else {
                const errorData = await response.json();
                console.error('Failed to update user details:', errorData.error);
            }
            })
            .catch((error) => {
            console.error('An unexpected error occurred:', error);
            });
        },
    },
  };
  </script>
  
<style scoped>
</style>
  