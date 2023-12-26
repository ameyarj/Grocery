<template>
  <div>
    <Navbar />
    <div class="add-category">
      <h2>Add Category</h2>
      <form @submit.prevent="addCategory">
        <div class="form-group">
          <label for="title">Title:</label>
          <input v-model="category.title" type="text" id="title" class="form-control" />
        </div><br/>
        <div class="form-group">
          <label for="description">Description:</label>
          <textarea v-model="category.description" id="description" class="form-control"></textarea>
        </div><br/>
        <div class="form-group">
          <label for="image">Image:</label>
          <input type="file" id="image" accept="image/*" @change="handleImageUpload" />
        </div>
        <div class="my-3">
          <button type="submit" class="btn btn-primary">Add</button>
        </div>
      </form>
      <div v-if="imagePreview" class="image-preview">
        <img :src="imagePreview" alt="Category Image" />
      </div>
      <div v-if="message" class="alert" :class="messageType">{{ message }}</div>
    </div>
  </div>
</template>

<script>
import Navbar from "../components/NavbarComponent";

export default {
  name: "AddCategory",
  data() {
    return {
      category: {
        title: "",
        description: "",
        image: null, 
      },
      imagePreview: null, 
      message: "",
      messageType: "",
    };
  },
  components: {
    Navbar,
  },
  methods: {
    async addCategory() {
      try {
        const token = localStorage.getItem("token");

        if (!this.category.title) {
          this.message = "Title is required.";
          this.messageType = "alert-danger";
          return;
        }

        const formData = new FormData();
        formData.append("title", this.category.title);
        formData.append("description", this.category.description);
        if (this.category.image) {
        formData.append("image", this.category.image,this.category.image.name);
      }

        const response = await fetch("http://localhost:5000/admin/create-category", {
          method: "POST",
          headers: {
            Authorization: "Bearer " + token,
          },
          body: formData, 
        });

        if (response.ok) {
          this.message = "Category added successfully.";
          this.messageType = "alert-success";
          this.category.title = "";
          this.category.description = "";
          this.category.image = null;
          this.imagePreview = null;
        } else {
          this.message = "Failed to add category.";
          this.messageType = "alert-danger";
          console.error("Failed to add category:", response.status);
        }
      } catch (error) {
        console.error("An error occurred:", error);
      }
    },
    handleImageUpload(event) {
      const file = event.target.files[0];
      if (file) {
        this.category.image = file;
      }
    },
  },
  beforeRouteEnter(to, from, next) {
    const token = localStorage.getItem("token");
    if (!token) {
      next({ name: "AdminLogin" });
    } else {
      next();
    }
  },
};
</script>

<style>
.image-preview {
  margin-top: 10px;
  max-width: 100%;
  height: auto;
}
</style>
