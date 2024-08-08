using System.ComponentModel.DataAnnotations;


    public class RegisterUserDTO
    {
        [Required(ErrorMessage = "User name is required")]
        [MinLength(3)]
        [MaxLength(255)]
        public string Name { get; set; }

        [Required(ErrorMessage = "Email is required")]
        [MinLength(4)]
        [MaxLength(255)]
        public string Email {  get; set; }

       
        [Required(ErrorMessage = "Password is required")]
        [MinLength(8)]
        [MaxLength(255)]
        public string Password { get; set; }

        
        

    }

