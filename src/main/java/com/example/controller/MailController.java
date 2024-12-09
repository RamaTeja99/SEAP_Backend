package com.example.controller;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import com.example.entity.MailRequest;
import com.example.service.MailService;

@RestController
@RequestMapping("/api/mail")
@CrossOrigin(origins = "https://seap.netlify.app", allowedHeaders = "*")
public class MailController {

    @Autowired
    private MailService mailService;

    @PostMapping("/send")
    public String sendMail(@RequestBody MailRequest mailRequest) {
        try {
            mailService.sendEmail(mailRequest.getTo(), mailRequest.getSubject(), mailRequest.getText());
            return "Mail sent successfully!";
        } catch (Exception e) {
            e.printStackTrace();
            return "Error while sending mail: " + e.getMessage();
        }
    }
}
