<template>
  <div>
    <Navbar />
    <div class="admin-dashboard">
      <h2>Welcome to the Admin Dashboard</h2>
      <h3>Signup Requests:</h3>
      <div v-if="message" :class="messageType" class="alert-message">
        {{ message }}
      </div>
      <table class="table">
        <thead>
          <tr>
            <th>Username</th>
            <th>Email</th>
            <th>Status</th>
            <th>Action</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="request in pendingRequests" :key="request.id">
            <td>{{ request.username }}</td>
            <td>{{ request.email }}</td>
            <td>{{ request.status }}</td>
            <td>
              <button
                @click="approveRequest(request.id)"
                class="btn btn-success"
              >
                Approve
              </button>
              <button @click="rejectRequest(request.id)" class="btn btn-danger">
                Reject
              </button>
            </td>
          </tr>
        </tbody>
      </table><br>
      <hr>
        <h3>Category Requests:</h3>
        <table class="table">
          <thead>
            <tr>
              <th>Title</th>
              <th>Description</th>
              <th>Image</th>
              <th>Action</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="request in categoryRequests" :key="request.id">
              <td>{{ request.title }}</td>
              <td>{{ request.description }}</td>
              <td><img :src="getImageURL(request)" width="30px" /></td>
              <td>
                <button @click="approveCategoryRequest(request.id)" class="btn btn-success">
                  Approve
                </button>
                <button @click="rejectCategoryRequest(request.id)" class="btn btn-danger">
                  Reject
                </button>
              </td>
            </tr>
          </tbody>
        </table><hr/>
        <div class="category-actions">
        <h3>Category Actions:</h3>
        <div class="row">
          <div class="col-md-6">
            <div class="card" style="width: 18rem">
              <img
                class="card-img-top"
                src="add-category.png"
                alt="Card image cap"
              />
              <div class="card-body">
                <h5 class="card-title">Add Category</h5>
                <button @click="goToAddCategory" class="btn btn-primary">
                  Add
                </button>
              </div>
            </div>
          </div>
          <div class="col-md-6">
            <div class="card" style="width: 18rem">
              <img
                class="card-img-top"
                src="edit-category.png"
                alt="Card image cap"
              />
              <div class="card-body">
                <h5 class="card-title">Edit Category</h5>
                <button @click="goToEditCategory" class="btn btn-warning">
                  Edit
                </button>
              </div>
            </div>
          </div>
        </div>
      </div><hr>
      <h3> Messages from Store Manager: </h3>
        <div v-for="message in storeManagerMessages" :key="message.id" class="message-container">
          <div class="message-header">
          <strong>Sender: </strong>{{ message.sender_username }}
        </div>
        <div class="message-content">
          <strong>Title: </strong>{{ message.title }}<br>
          <strong>Body: </strong>{{ message.body }}<br>
          <strong>Sent at: </strong>{{ message.timestamp }}
        </div>
        <button @click="markAsRead(message.id)" class="btn btn-primary">Mark as Read</button>
        </div>
    
    </div>
  </div>
</template>

<script>
import Navbar from "../components/NavbarComponent";

export default {
  name: "AdminDashboard",
  data() {
    return {
      pendingRequests: [],
      categoryRequests: [],
      message: "",
      messageType: "",
      storeManagerMessages: [],
    };
  },
  components: {
    Navbar,
  },
  mounted() {
    this.fetchAllRequests();
    this.fetchCategoryRequests();
    this.fetchStoreManagerMessages();

    
  },
  methods: {
    async fetchStoreManagerMessages() {
    try {
      const token = localStorage.getItem("token");
      const response = await fetch("http://localhost:5000/admin/get-messages", {
        method: "GET",
        headers: {
          Authorization: "Bearer " + token,
        },
      });

      if (response.ok) {
        const data = await response.json();
        this.storeManagerMessages = data.messages;
      } else {
        console.error("Failed to fetch store manager messages:", response.status);

          // this.message = "Failed to fetch store manager messages";
          // this.messageType = "error";
      }
    } catch (error) {
      console.error("An error occurred while fetching store manager messages:", error);
      this.message = "An error occurred while fetching store manager messages";
      this.messageType = "error";
    }
  },
  async markAsRead(messageId) {
  try {
    const token = localStorage.getItem("token");
    const response = await fetch(`http://localhost:5000/admin/mark-as-read`, {
      method: "PUT",
      headers: {
        Authorization: "Bearer " + token,
        "Content-Type": "application/json",  
      },
      body: JSON.stringify({ message_id: messageId }),  
    });

    if (response.ok) {
      this.storeManagerMessages = this.storeManagerMessages.filter(message => message.id !== messageId);
    } else {
      console.error("Failed to mark message as read:", response.status);
      this.message = "Failed to mark the message as read";
      this.messageType = "error";
    }
  } catch (error) {
    console.error("An error occurred while marking as read:", error);
    this.message = "An error occurred while marking the message as read";
    this.messageType = "error";
  }
},

    async fetchAllRequests() {
      try {
        this.message = "";
        this.messageType = "";
        this.loading = true;
        const token = localStorage.getItem("token");
        console.log("Token being fetched:", token);

        const response = await fetch(
          "http://localhost:5000/admin/all-requests",
          {
            method: "GET",
            headers: {
              Authorization: "Bearer " + token,
            },
          }
        );

        if (response.ok) {
          const data = await response.json();
          this.pendingRequests = data;
        } else {
          const errorMessage = await response.text();
          console.log(errorMessage);
          this.message = "Failed to fetch requests.";
          this.messageType = "alert-danger";
          console.error("Failed to fetch requests:", response.status);
        }
      } catch (error) {
        console.error("An error occurred:", error);
        this.message = "An error occurred while fetching requests.";
        this.messageType = "alert-danger";
      }
    },
    async fetchCategoryRequests() {
      try {
        const token = localStorage.getItem("token");
        const response = await fetch("http://localhost:5000/admin/category-requests", {
          method: "GET",
          headers: {
            Authorization: "Bearer " + token,
          },
        });

        if (response.ok) {
          const data = await response.json();
          this.categoryRequests = data;
        } else {
          const errorMessage = await response.text();
          console.log(errorMessage);
          this.message = "Failed to fetch Category requests.";
          this.messageType = "alert-danger";
          console.error("Failed to fetch Category requests:", response.status);
        }
      } catch (error) {
        console.error("An error occurred:", error);
        this.message = "An error occurred while fetching Category requests.";
        this.messageType = "alert-danger";
      }
    },
    async approveCategoryRequest(requestId) {
  try {
    const token = localStorage.getItem("token");
    const response = await fetch(`http://localhost:5000/admin/approve-category-request/${requestId}`, {
      method: "PUT",
      headers: {
        Authorization: "Bearer " + token,
      },
    });

    if (response.ok) {
      this.message = "Category request approved";
      this.messageType = "success";
      window.location.reload();
    } else {
      this.message = "Failed to approve category request";
      this.messageType = "error";
      window.location.reload();

    }
  } catch (error) {
    console.error("An error occurred:", error);
    this.message = "An error occurred while approving category request";
    this.messageType = "error";
  }
},

async rejectCategoryRequest(requestId) {
      try {
        const token = localStorage.getItem("token");
        const response = await fetch(`
        http://localhost:5000/admin/reject-category-request/${requestId}`,
         {
          method: "PUT",
          headers: {
            Authorization: "Bearer " + token,
          },
        });

        if (response.ok) {
          this.message = "Category request rejected";
          this.messageType = "success";
          window.location.reload();
        } else {
          this.message = "Failed to reject category request";
          this.messageType = "error";
          window.location.reload();

        }
      } catch (error) {
        console.error("An error occurred:", error);
        
      }
    },
    getImageURL(request) {
      return (
        request.image_filename || " "
      );
    },
    async approveRequest(requestId) {
      try {
        const token = localStorage.getItem("token");
        console.log("Token being fetched:", token);

        const response = await fetch(
          `http://localhost:5000/admin/approve/${requestId}`,
          {
            method: "PUT",
            headers: {
              Authorization: "Bearer " + token,
            },
          }
        );
        console.log(response);

        if (response.ok) {
          this.message = "Request approved successfully.";
          this.messageType = "alert-success";
          this.fetchAllRequests();
        } else {
          this.message = "Failed to approve request.";
          this.messageType = "alert-danger";
          console.error("Failed to approve request:", response.status);
        }
      } catch (error) {
        console.error("An error occurred:", error);
      }
    },

    async rejectRequest(requestId) {
      try {
        const token = localStorage.getItem("token");
        console.log("Token being fetched:", token);

        const response = await fetch(
          `http://localhost:5000/admin/reject/${requestId}`,
          {
            method: "PUT",
            headers: {
              Authorization: "Bearer " + token,
            },
          }
        );
        console.log(response);
        if (response.ok) {
          this.message = "Request rejected successfully.";
          this.messageType = "alert-success";
          this.fetchAllRequests();
        } else {
          this.message = "Failed to reject request.";
          this.messageType = "alert-danger";
          console.error("Failed to reject request:", response.status);
        }
      } catch (error) {
        console.error("An error occurred:", error);
      }
    },

    goToAddCategory() {
      this.$router.push({ name: "AddCategory" });
      this.$router.go();
    },

    goToEditCategory() {
      this.$router.push({ name: "EditCategory" });
      this.$router.go();
    },
  },
};
</script>
<style scoped>
.message-container {
  border: 1px solid #ddd;
  margin: 10px 0;
  padding: 10px;
  border-radius: 5px;
}

.message-header {
  font-size: 14px;
  color: #555;
  margin-bottom: 5px;
}

.message-content {
  font-size: 16px;
  margin-bottom: 10px;
}


</style>
