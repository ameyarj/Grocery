<template>
  <div>
    <Navbar />
    <h2>Categories:</h2>
    <div class="edit-category">
      <div v-if="categories.length > 0">
        <table class="table">
          <thead>
            <tr>
              <th>Category ID</th>
              <th>Title</th>
              <th>Description</th>
              <th>Image</th>
              <th class="heading-5"></th>
              <th>Actions</th>
            </tr>
          </thead>

          <tbody>
            <tr v-for="category in categories" :key="category.id">
              <td>{{ category.id }}</td>
              <td>
                <span v-if="!category.isEditing">{{ category.title }}</span>
                <input v-else v-model="category.editedTitle" />
              </td>
              <td>
                <span v-if="!category.isEditing">{{
                  category.description
                }}</span>
                <input v-else v-model="category.editedDescription" />
              </td>
              <td>
                <img :src="getImageURL(category)" width="30px" />
              </td>
              <td>
                <input
                  type="file"
                  @change="handleImageUpload(category, $event)"
                  accept="image/*"
                  v-if="category.isEditing"
                />
              </td>
              <td colspan="2">
                <button
                  class="btn btn-warning"
                  @click="toggleEdit(category)"
                  v-if="!category.isEditing"
                >
                  Edit
                </button>
                <button
                  class="btn btn-success"
                  @click="saveChanges(category)"
                  v-if="category.isEditing"
                >
                  Save
                </button>
                <button class="btn btn-danger"  @click="confirmDelete(category)">Delete</button>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>
  </div>
</template>

<script>
import Navbar from "../components/NavbarComponent";

export default {
  name: "EditCategory",
  data() {
    return {
      categories: [],
      message: "",
      messageType: "",
      selectedImage: null,
    };
  },
  components: {
    Navbar,
  },
  mounted() {
    this.fetchCategories();
  },
  methods: {
    async fetchCategories() {
      try {
        const token = localStorage.getItem("token");
        const response = await fetch("http://localhost:5000/api/categories", {
          method: "GET",
          headers: {
            Authorization: "Bearer " + token,
          },
        });

        if (response.ok) {
          const data = await response.json();
          this.categories = data.map((category) => ({
            ...category,
            isEditing: false,
            editedTitle: category.title,
            editedDescription: category.description,
            selectedImage: null,
          }));
        } else {
          this.message = "Failed to fetch categories.";
          this.messageType = "alert-danger";
          console.error("Failed to fetch categories:", response.status);
        }
      } catch (error) {
        console.error("An error occurred:", error);
        this.message = "An error occurred while fetching categories.";
        this.messageType = "alert-danger";
      }
    },

    getImageURL(category) {
      return (
        category.image_filename || " "
      );
    },
    handleImageUpload(category, event) {
      const file = event.target.files[0];
      if (file) {
        category.selectedImage = file;
      }
    },
    toggleEdit(category) {
      category.isEditing = !category.isEditing;
    },

    async saveChanges(category) {
      try {
        const token = localStorage.getItem("token");
        const categoryId = category.id;

        const formData = new FormData();
        formData.append("title", category.editedTitle);
        formData.append("description", category.editedDescription);

        if (category.selectedImage) {
          formData.append(
            "image",
            category.selectedImage,
            category.selectedImage.name
          );
        }

        const response = await fetch(
          `http://localhost:5000/admin/edit-category/${categoryId}`,
          {
            method: "PUT",
            headers: {
              Authorization: "Bearer " + token,
            },
            body: formData,
          }
        );

        if (response.ok) {
          this.message = "Category updated successfully.";
          this.messageType = "alert-success";
          category.title = category.editedTitle;
          category.description = category.editedDescription;
          category.selectedImage = null;
          category.isEditing = false;
        } else {
          this.message = "Failed to update category.";
          this.messageType = "alert-danger";
          console.error("Failed to update category:", response.status);
        }
      } catch (error) {
        console.error("An error occurred:", error);
      }
    },
    async deleteCategory(category) {
      try {
        const token = localStorage.getItem("token");
        const categoryId = category.id;

        const response = await fetch(
          `http://localhost:5000/admin/delete-category/${categoryId}`,
          {
            method: "DELETE",
            headers: {
              Authorization: "Bearer " + token,
            },
          }
        );

        if (response.ok) {
          this.message = "Category deleted successfully.";
          this.messageType = "alert-success";
          this.categories = this.categories.filter((c) => c.id !== categoryId);
        } else {
          this.message = "Failed to delete category.";
          this.messageType = "alert-danger";
          console.error("Failed to delete category:", response.status);
        }
      } catch (error) {
        console.error("An error occurred:", error);
      }
    },

    async confirmDelete(category) {
      const confirmDelete = window.confirm(
        `Are you sure you want to delete the category "${category.title}"?`
      );

      if (confirmDelete) {
        this.deleteCategory(category);
      }
    },
  },
};
</script>

<style>
.heading-5{
  padding-left: 600px;
}
</style>
