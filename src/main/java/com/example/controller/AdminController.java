package com.example.controller;

import com.example.entity.College;
import com.example.entity.Student;
import com.example.entity.User;
import com.example.entity.Achievement;
import com.example.service.CollegeService;
import com.example.service.StudentService;
import com.example.service.UserService;
import com.example.service.AchievementService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/admin")
@CrossOrigin(origins = "https://seap.netlify.app", allowedHeaders = "*")
public class AdminController {
	@Autowired
    private CollegeService collegeService;
	@Autowired
    private StudentService studentService;
	@Autowired
    private AchievementService achievementService;
	@Autowired
	private UserService userService;
	
	// Get total college count
	@GetMapping("/colleges/count")
	public long getCollegeCount() {
	    return collegeService.count();
	}

	// Get total student count
	@GetMapping("/students/count")
	public long getStudentCount() {
	    return studentService.count();
	}

	// Get total achievement count
	@GetMapping("/achievements/count")
	public long getAchievementCount() {
	    return achievementService.count();
	}


    // Add College
    @PostMapping("/colleges")
    public College addCollege(@RequestBody College college) {
        return collegeService.save(college);
        
    }
    // Add College User
    @PostMapping("/addcollegeuser")
    public User addCollegeUser(@RequestBody User user) {
    	  System.out.println("Admin "+user);
    	  return userService.save(user);
    }

    // Get All Colleges
    @GetMapping("/colleges")
    public List<College> getColleges() {
        return collegeService.findAll();
        
    }
    // Get College By ID
    @GetMapping("/colleges/{id}")
    public College getCollegeById(@PathVariable Long id) {
        return collegeService.findById(id);
    }
    // Get College User By ID
    @GetMapping("/college-user/{collegeId}")
    public User getCollegeUserByCollegeId(@PathVariable int collegeId) {
        return userService.getCollegeUserByCollegeId(collegeId);
    }

    

    // Get All Students
    @GetMapping("/students")
    public List<Student> getStudents() {
        return studentService.findAll();
    }

    // Get All Achievements
    @GetMapping("/achievements")
    public List<Achievement> getAllAchievements() {
        return achievementService.findAll();
    }

    // Update College
    @PutMapping("/colleges/{id}")
    public College updateCollege(@PathVariable Long id, @RequestBody College college) {
        return collegeService.update(id, college);
    }
    // Update College User Credentials
    @PutMapping("/update-college-credentials/{collegeId}")
    public String updateCollegeCredentials(@PathVariable int collegeId,
                                           @RequestParam String newUsername,
                                           @RequestParam String newPassword) {
        userService.updateCollegeCredentialsByAdmin(collegeId, newUsername, newPassword);
        return "College credentials updated successfully";
    }
    //Delete College Based on ID
    @DeleteMapping("/colleges/{id}")
    public void deleteCollege(@PathVariable Long id) {
    	System.out.println("Deleted College and Students and Achievements");
    	List<Student> students = studentService.findByCollegeId(id);
        for (Student student : students) {
            List<Achievement> achievements = achievementService.findByStudentId(student.getId());
            for (Achievement achievement : achievements) {
                achievementService.delete(achievement.getId());
            }
            studentService.delete(student.getId());
        }
        collegeService.delete(id);
        
        
    }
    //Delete College User Based on ID
    @DeleteMapping("/collegesuser/{id}")
    public void deleteCollegeUser(@PathVariable Long id) {
    	System.out.println("Deleted College User and Student User");
    	List<Student> students = studentService.findByCollegeId(id);
    	for (Student student : students) {
    		userService.deleteStudentUserByStudentId(student.getId().intValue());
    	}
    	userService.deleteCollegeUserByCollegeId(id.intValue());
    }
    
   

}
