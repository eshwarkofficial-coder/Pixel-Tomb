// Image preview
const imageInput = document.querySelector('input[name="image"]');
let preview = document.getElementById("preview");

if (imageInput) {
    imageInput.addEventListener("change", function () {
        const file = this.files[0];
        if (file) {
            if (!preview) {
                preview = document.createElement('img');
                preview.id = 'preview';
                preview.style.maxWidth = '100%';
                preview.style.marginTop = '15px';
                preview.style.borderRadius = '8px';
                preview.style.border = '1px solid #dae1e7';
                // Insert after the input
                this.parentNode.insertBefore(preview, this.nextSibling);
            }
            preview.src = URL.createObjectURL(file);
        }
    });
}
