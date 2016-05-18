<?php

class UsersController extends AppController {

    public $name = 'Users';
    public $uses = array('User','EmailTemplate','Cuisine','Dish','Restaurant','RestaurantsFavourites','Configuration','Country','AppUser');
    public $helpers = array('Html', 'Form', 'Session');
    public $components = array('General','Upload', 'Cookie', 'Email', 'Captcha', 'Auth' => array(
                'authenticate' => array(
                    'Form' => array(
                        'scope' => array('User.status' => '1')
                    )
                )
            ));

    public function beforeFilter() {
        parent::beforeFilter();
        $this->Auth->allow('login','welcome','activate','account_error', 'admin_login', 'captcha','admin_forgot_password','admin_reset_password','forgot_pass','reset_password','check_unique_email','process','activate','fill_states','get_encrypt','get_decrypt');
    }

    public function captcha() {
        $this->autoRender = false;
        $this->layout = 'plain';

        $this->Captcha->create();
    }
	
    public function admin_login(){

        $this->layout = 'admin_login';
        if ($this->Session->read('Auth.User')) {

            $this->redirect(array('admin' => true, 'controller' => 'users', 'action' => 'dashboard'));
        }

        if ($this->request->is('post')) {
            if ($this->Auth->login()) {
				$this->redirect(array('admin' => true, 'controller' => 'users', 'action' => 'dashboard'));
            }
            else {
                $this->Session->write('msg_type', 'alert-danger');
                $this->Session->setFlash(__('Invalid Email/Username or Password.'));
            }
        }
    }
    
    public function admin_forgot_password(){

        $this->layout = 'admin_login';
        $msgString = "";
        
        if ($this->request->is('post')) {
            
            if (empty($this->request->data["User"]["email_address"])) {
                $msgString .="Please enter an email address.<br>";
            } 
            elseif ($this->User->checkEmail($this->request->data["User"]["email_address"]) == false) {
                $msgString .="Please enter a valid email address.<br>";
            }
            elseif ($this->User->isRecordUniqueemail($this->request->data["User"]["email_address"]) == true) {
                $msgString .="Email not found.<br>";
            }
            
            if (isset($msgString) && $msgString != '') {
                $this->Session->write('msg_type', 'alert-danger');
                $this->Session->setFlash($msgString);
            } 
            else {
                $password_token = time();
                $user_detail = $this->User->findByEmailAddress($this->request->data["User"]["email_address"]);
               
                $userSaveArrar =array();
                $userSaveArrar['User']['id']=$user_detail['User']['id'];
                 $userSaveArrar['User']['password_token']=$password_token;
                 
         
                $this->User->save($userSaveArrar);
             
                
                $password_token_url = '<a href="'.Configure::read('Site.url').'/admin/users/reset_password/'.$password_token.'">Change Password</a>';
                // start mail code

                $email_template_detail = $this->EmailTemplate->find('first', array('conditions' => array('EmailTemplate.email_type' => 'forgot_password')));

                $email_template = $email_template_detail['EmailTemplate']['message'];
              /*  $sender_email = $email_template_detail['EmailTemplate']['sender_email'];
                $subject = $email_template_detail['EmailTemplate']['subject'];
                $sender_name = $email_template_detail['EmailTemplate']['sender_name'];*/

                $email_template = str_replace('[site_title]', Configure::read('Site.title'), $email_template);
                $email_template = str_replace('[email]', $this->request->data['User']['email_address'], $email_template);
                $email_template = str_replace('[password_change_url]', $password_token_url, $email_template);

                
                                        $to = $this->request->data['User']['email_address'];
					$subject = $email_template_detail['EmailTemplate']['subject'];
					$message = $email_template;
					$from =  $email_template_detail['EmailTemplate']['sender_email'];
					$fromName =$email_template_detail['EmailTemplate']['sender_name'];
					$delivery = 'smtp';
					$replyTo = $email_template_detail['EmailTemplate']['sender_email'];
					$replyName = $email_template_detail['EmailTemplate']['sender_name'];
                    $bcc = array();
                    $template = 'default';
                    $sendAs = 'html';
                    
                    
                    
                    $this->_send_mail($to, $subject, $message, $from, $fromName, $delivery, $replyTo, $replyName, $bcc, $template, $sendAs);
                    
                    
             
                /*$this->Email->to = $this->request->data['User']['email_address'];
                $this->Email->subject = $subject;
                $this->Email->replyTo = $sender_name . "<" . $sender_email . ">";
                $this->Email->from = $sender_name . "<" . $sender_email . ">";

                $this->Email->sendAs = 'html';
                $this->Email->template = 'default';

                $this->set('message', $email_template);

                $this->Email->send();
                */

                // end mail code  

                $this->Session->write('msg_type', 'alert-success');
                $this->Session->setFlash(__('You will receive an email with instructions about how to reset your password in a few minutes.'));
                $this->redirect(array('controller' => 'users', 'action' => 'login'));
            }
        }
    }
    
    public function admin_reset_password($password_token=null){

        $this->layout = 'admin_login';
        $msgString = "";
        
        $user_detail = $this->User->findByPasswordToken($password_token);
        
        if(empty($user_detail))
        {
            $this->Session->write('msg_type', 'alert-danger');
            $this->Session->setFlash(__('Invalid Token.'));
        }
        
      //  pr($user_detail);
        
        
        if ($this->request->is('post')) {
            
            if (empty($this->request->data["User"]["password"])) {
                $msgString .="Please enter a password.<br>";
            } 
            elseif (strlen($this->request->data["User"]["password"]) < 5) {
                $msgString .="Your password must be at least 5 characters long.<br>";
            }

            if (empty($this->request->data["User"]["confirm_password"])) {
                $msgString .="Please enter confirm password.<br>";
            }

            $password = $this->request->data["User"]["password"];
            $conformpassword = $this->request->data["User"]["confirm_password"];

            if ($password != $conformpassword) {
                $msgString.= "The password doesn't match confirmation.<br>";
            }
            
            if (isset($msgString) && $msgString != '') {
                $this->Session->write('msg_type', 'alert-danger');
                $this->Session->setFlash($msgString);
            } 
            else {
                
                $this->request->data["User"]["id"] = $user_detail['User']['id'];
		$password = $this->request->data["User"]['password'];
                $this->request->data["User"]['password'] = AuthComponent::password($this->request->data["User"]['password']);
                //pr($this->request->data);
               //die();
                $this->User->save($this->request->data);
				
				// -------------- Pay to shopper Email Alerts --------------
					//$configuration = $this->Configuration->getConfigurationValues();
					$search = array('[username]','[new_password]','[email_address]');
					$replace = array(
						$user_detail['User']['email_address'],
						$password,
						$user_detail['User']['email_address'],
					);

					$email_template = $this->EmailTemplate->get_template('new_password_email', $search, $replace);
					
					if (!empty($email_template)) {
						$to 		= $user_detail['User']['email_address'];
						$subject 	= $email_template['subject'];
						$message 	= $email_template['message'];
						$from 		= $email_template['sender_email'];
						$fromName 	= $email_template['sender_name'];
						$delivery 	= 'smtp';
						$replyTo 	= $email_template['sender_email'];
						$replyName 	= $email_template['sender_name'];
						$bcc 		= array();
						$template 	= 'default';
						$sendAs 	= 'html';
						//prd($message);
						$this->_send_mail($to, $subject, $message, $from, $fromName, $delivery, $replyTo, $replyName, $bcc, $template, $sendAs);
					}
				// -------------- Pay to shopper Email Alerts --------------
				
                $this->Session->write('msg_type', 'alert-success');
                $this->Session->setFlash(__('Your password has been changed successfully.'));
                $this->redirect(array('controller' => 'users', 'action' => 'login'));
                
            }
        }
        
        $this->set('password_token',$password_token);
    }

    public function admin_settings(){

        $this->layout = 'admin';
        $msgString = "";
        $leftnav = "settings";
        $this->set(compact('leftnav'));
        
        $this->User->id = $this->Session->read('Auth.User.id');
        $this->set('user_detail',$this->User->read());
        
        if ($this->request->is('post')) {
				
			if (empty($this->request->data["User"]["password"])) {
                $msgString .="Please enter old password.<br>";
            }else{
				$oldpassword = AuthComponent::password($this->request->data["User"]["oldpassword"]);
				$uid = Configure::read('UserData.User.id');
				$user_data = $this->User->read(null, $uid);
				
				if(!empty($user_data)){
					if($oldpassword != $user_data['User']['password'] ){
						$msgString .="Wrong old password.<br>";
					}
				}
			} 
			
            if (empty($this->request->data["User"]["password"])) {
                $msgString .="Please enter a password.<br>";
            } 
            elseif (strlen($this->request->data["User"]["password"]) < 5) {
                $msgString .="Your password must be at least 5 characters long.<br>";
            }

            if (empty($this->request->data["User"]["confirm_password"])) {
                $msgString .="Please enter confirm password.<br>";
            }

            $password = $this->request->data["User"]["password"];
            $conformpassword = $this->request->data["User"]["confirm_password"];

            if ($password != $conformpassword) {
                $msgString.= "The password doesn't match confirmation.<br>";
            }
            
            if (isset($msgString) && $msgString != '') {
                $this->Session->write('msg_type', 'alert-danger');
                $this->Session->setFlash($msgString);
            } 
            else {
                $this->request->data["User"]["password"] = AuthComponent::password($this->request->data["User"]["password"]);
                $this->request->data["User"]["id"] = $this->Session->read('Auth.User.id');
                
                $this->User->save($this->request->data);
                $this->Session->write('msg_type', 'alert-success');
                $this->Session->setFlash(__('Your password has been changed successfully.'));
                $this->redirect(array('controller' => 'users', 'action' => 'settings'));
            }
        }
    }
    
    public function admin_change_password($user_id){

        $this->layout = 'admin';
        $msgString = "";
        $this->set(compact('leftnav'));
        
        $this->User->id = $user_id;
        $user_detail = $this->User->read();
        $this->set('user_detail',$user_detail);
        if ($this->request->is('post')) {
            
            if (empty($this->request->data["User"]["password"])) {
                $msgString .="Please enter a password.<br>";
            } 
            elseif (strlen($this->request->data["User"]["password"]) < 5) {
                $msgString .="Your password must be at least 5 characters long.<br>";
            }

            if (empty($this->request->data["User"]["confirm_password"])) {
                $msgString .="Please enter confirm password.<br>";
            }

            $password = $this->request->data["User"]["password"];
            $conformpassword = $this->request->data["User"]["confirm_password"];

            if ($password != $conformpassword) {
                $msgString.= "Password doesn't match confirmation.<br>";
            }
            
            if (isset($msgString) && $msgString != '') {
                $this->Session->write('msg_type', 'alert-danger');
                $this->Session->setFlash($msgString);
            } 
            else {
                
                $this->request->data["User"]["id"] = $user_id;
		$this->request->data["User"]['password'] = AuthComponent::password($this->request->data["User"]['password']);	 
                $this->User->save($this->request->data);
                $this->Session->write('msg_type', 'alert-success');
                $this->Session->setFlash(__('User password has been changed successfully.'));
				$userInfo = $this->User->find('first',array(
				'conditions'=>array(
					'User.id'=>$user_id,
				)
			)); 
				//pr($userInfo);
				// -------------- Invoice Email Alerts --------------
                //$configuration = $this->Configuration->getConfigurationValues();
                $search = array('[username]','[email_address]','[new_password]');
                $replace = array(
                    $userInfo['User']['full_name'],
                    $userInfo['User']['email_address'],
                    $password
					
                );

                $email_template = $this->EmailTemplate->get_template('new_password_email', $search, $replace);

                if (!empty($email_template)) {
					$to = $userInfo['User']['email_address'];
					$subject = $email_template['subject'];
					$message = $email_template['message'];
					$from = $email_template['sender_email'];
					$fromName = $email_template['sender_name'];
					$delivery = 'smtp';
					$replyTo = $email_template['sender_email'];
					$replyName = $email_template['sender_name'];
                    $bcc = array();
                    $template = 'default';
                    $sendAs = 'html';
					
					//echo $message;
					//die();
                    $this->_send_mail($to, $subject, $message, $from, $fromName, $delivery, $replyTo, $replyName, $bcc, $template, $sendAs);
                }
			// -------------- Invoice Email Alerts --------------
				
				
				
				
				//exit;
                if($user_detail['User']['role_id'] == '3')
                {
                    $this->redirect(array('controller' => 'users', 'action' => 'index'));
                }
                else
                {
                    //$this->redirect(array('controller' => 'users', 'action' => 'sub_admin'));
					$this->redirect(array('controller' => 'users', 'action' => 'index'));
                }
            }
        }
    }


    public function admin_dashboard(){
			
        $this->layout = 'admin_dashboard';
        $leftnav = "dashboard";
        $this->set(compact('leftnav'));
		App::uses('Sanitize','Utility');
	
		$conditionApp		= array();
		$conditionUser		= array('User.role_id'=>'2');
		$conditionDish		= array();
		$conditionCuisine	= array();
		$conditionRest		= array();
         if (!empty($this->request->data)) {
			
			if (isset($this->request->data['User']['date_from']) && $this->request->data['User']['date_from'] != '') {
                $fromDate = Sanitize::clean(trim($this->data['User']['date_from']));
               
            }
          
			if (isset($this->request->data['User']['date_to']) && $this->request->data['User']['date_to'] != '') {
                $toDate = Sanitize::clean(trim($this->data['User']['date_to']));
               
            }
           
			
			if (isset($this->request->data['User']['date_range']) && $this->request->data['User']['date_range'] != '') {
                $dateRange = Sanitize::clean(trim($this->data['User']['date_range']));
            }
		  
		   if (!isset($dateRange) && isset($fromDate) && $fromDate!= '' &&  isset($toDate) &&  $toDate!='' ) {
				function getDateCondition($fromDate,$toDate,$table){		  
					
					$dateCond = '';
					 
					$dateCond = " ( DATE_FORMAT($table.created,'%Y-%m-%d') between '" .date("Y-m-d",strtotime($fromDate)) . "' AND  '" . date("Y-m-d",strtotime($toDate)) . " ' ) "; 
				
					return $dateCond;
				
				}
				
				$conditionApp  		= getDateCondition($fromDate,$toDate,$table='AppUser');
				$conditionUser 		= getDateCondition($fromDate,$toDate,$table='User');
				$conditionDish  	= getDateCondition($fromDate,$toDate,$table='Dish');
				$conditionRest 		= getDateCondition($fromDate,$toDate,$table='Restaurant');
				$conditionCuisine	= getDateCondition($fromDate,$toDate,$table='Cuisine');
					
					
		   }
		   
		   
		  if (isset($dateRange) && $dateRange != '') {
			function getRangeCondition($dateRange,$table){		  
					
					$dateCond = '';
					if($dateRange=='today'){
					   $dateCond = " ( DATE_FORMAT($table.created,'%Y-%m-%d') = '" .date("Y-m-d") . "' ) "; 
					}
					else if($dateRange=='week'){
					   $lastWeek = date('Y-m-d',strtotime('last Week'));  
					   $dateCond = " ( DATE_FORMAT($table.created,'%Y-%m-%d') between '" .$lastWeek . "' AND  '" . date("Y-m-d") . " ' ) "; 
					}
					else if($dateRange=='month'){
					   $lastMonth = date('Y-m-d',strtotime('last Month'));  
					   $dateCond = " ( DATE_FORMAT($table.created,'%Y-%m-%d') between '" .$lastMonth . "' AND  '" . date("Y-m-d") . " ' ) "; 
					}
					else if($dateRange=='year'){
					   $lastYear = date('Y-m-d',strtotime('last Year'));  
					   $dateCond = " ( DATE_FORMAT($table.created,'%Y-%m-%d') between '" .$lastYear . "' AND  '" . date("Y-m-d") . " ' ) "; 
					}
					
					
			   
					return $dateCond;
				   
				 
			}
			
				// all conditions
				$conditionApp  		= getRangeCondition($dateRange,$table='AppUser');
				$conditionUser 		= getRangeCondition($dateRange,$table='User');
				$conditionDish  	= getRangeCondition($dateRange,$table='Dish');
				$conditionRest 		= getRangeCondition($dateRange,$table='Restaurant');
				$conditionCuisine	= getRangeCondition($dateRange,$table='Cuisine');
			  }
		 }
		 
        $this->set('total_users',$this->User->find('count',array('conditions'=>$conditionUser)));
		$this->set('total_dishes',$this->Dish->find('count',array('conditions'=>$conditionDish)));
		$this->set('total_restaurants',$this->Restaurant->find('count',array('conditions'=>$conditionRest)));
		$this->set('total_cuisines',$this->Cuisine->find('count',array('conditions'=>$conditionCuisine)));
		$this->set('total_app_launch',$this->AppUser->find('count',array('conditions'=>$conditionApp)));
    		
	}

    public function admin_profile(){
        $this->layout = 'admin';
        $msgString = "";
        $leftnav = "profile";
        $this->set(compact('leftnav'));
        
        $this->set('user_detail',$this->User->find('first',array('conditions'=>array('User.id'=>$this->Session->read('Auth.User.id')))));
        
        if ($this->request->is('post') || $this->request->is('put')) {
            
            if (empty($this->request->data["User"]["first_name"])) {
                $msgString .="First Name is required field.<br>";
            } 
            elseif (trim($this->request->data["User"]["first_name"]) == "") {
                $msgString .= "Please enter valid first name.<br>";
            }
            
            if (empty($this->request->data["User"]["last_name"])) {
                $msgString .="Last Name is required field.<br>";
            } 
            elseif (trim($this->request->data["User"]["last_name"]) == "") {
                $msgString .= "Please enter valid last name.<br>";
            }

            if (empty($this->request->data["User"]["email_address"])) {
                $msgString .="Email is required field.<br>";
            } 
            elseif ($this->User->checkEmail($this->request->data["User"]["email_address"]) == false) {
                $msgString .="Please enter valid Email.<br>";
            }
            elseif ($this->request->data["User"]["email_address"] != $this->request->data["User"]["old_email_address"]) {
                if ($this->User->isRecordUniqueemail($this->request->data["User"]["email_address"]) == false) {
                    $msgString .="Email already exists.<br>";
                }
            }
            
            if (isset($msgString) && $msgString != '') {
                $this->Session->write('msg_type', 'alert-danger');
                $this->Session->setFlash($msgString);
            } 
            else {
                
                $destination = realpath('../../app/webroot/img/uploads/users/') . '/';
                $file = $this->request->data['User']['image'];

                if (!empty($file['name'])) {
                    $this->Upload->upload($file, $destination, null);
                    $errors = $this->Upload->errors;

                    if (empty($errors)) {
                        $this->request->data['User']['image'] = $this->Upload->result;
						$this->request->data["User"]["profile_image"] = $this->request->data["User"]["image"];
                    } else {

                        if (is_array($errors)) {
                            $errors = implode("<br />", $errors);
                        }

                        $this->Session->write('msg_type', 'alert-danger');
                        $this->Session->setFlash($errors);
                        $this->redirect(array('admin' => true, 'controller' => 'users', 'action' => 'profile'));
                        exit();
                    }
                } 
                else {
                    unset($this->request->data['User']['image']);
                }
                
                $this->request->data["User"]["username"] = $this->request->data["User"]["email_address"];
                
                if ($this->User->save($this->request->data)) {
                    $this->Session->write('msg_type', 'alert-success');
                    $this->Session->setFlash(__('Your profile has been updated'));
                    $this->redirect(array('admin' => true, 'controller' => 'users', 'action' => 'profile'));
                }
            }
        }
        else
        {            
            $this->User->id = $this->Session->read('Auth.User.id');
            $this->request->data = $this->User->read();
            $this->request->data['User']['old_email_address'] = $this->request->data['User']['email_address'];
        }
    }
   
    public function admin_index($search_clear=null){
	
        $this->layout = 'admin';
        $leftnav = "users";
        $subleftnav = "view_user";
        $this->loadModel('Role');
		$roles = $this->Role->find('list',array('fields'=>array('id','role')));
		$countries = $this->Country->getContryList();
		$this->set(compact('countries'));
		
        $this->set(compact('leftnav','subleftnav','roles'));
        $condition = array('User.role_id' =>'2');
        $separator = array();
		
		App::uses('Sanitize','Utility');
		
		$countryList = $this->Country->find('list', array('fields' => array('countryName', 'countryName')));
        $this->set('countryList', $countryList);
		 
        if (isset($search_clear) && $search_clear == '1') {
            $this->Session->delete('Client');
            $this->redirect(array('admin' => true, 'controller' => 'users', 'action' => 'index'));
        }
        
        if (!empty($this->request->data)) {

            if (isset($this->request->data['User']['keyword']) && $this->request->data['User']['keyword'] != '') {
                $keyword = Sanitize::clean(trim($this->data['User']['keyword']));
                $this->Session->write('Client.keyword', $keyword);
            }
            else {
                $this->Session->delete('Client.keyword');
            }
			
			if (isset($this->request->data['User']['date_from']) && $this->request->data['User']['date_from'] != '') {
                $fromDate = Sanitize::clean(trim($this->data['User']['date_from']));
                $this->Session->write('Client.date_from', $fromDate);
            }
            else {
                $this->Session->delete('Client.date_from');
            }
			
			if (isset($this->request->data['User']['date_to']) && $this->request->data['User']['date_to'] != '') {
                $toDate = Sanitize::clean(trim($this->data['User']['date_to']));
                $this->Session->write('Client.date_to', $toDate);
            }
            else {
                $this->Session->delete('Client.date_to');
            }
			
			if (isset($this->request->data['User']['date_range']) && $this->request->data['User']['date_range'] != '') {
                $dateRange = Sanitize::clean(trim($this->data['User']['date_range']));
                $this->Session->write('Client.date_range', $dateRange);
            }
            else {
                $this->Session->delete('Client.date_range');
            }
			
			if (isset($this->request->data['User']['country']) && $this->request->data['User']['country'] != '') {
                $country = Sanitize::clean(trim($this->data['User']['country']));
                $this->Session->write('Client.country', $country);
            }
            else {
                $this->Session->delete('Client.country');
            }
			

            if (isset($this->request->data['User']['action'])) {
                $idList = $this->data['User']['idList'];
                if ($idList) {

                    if ($this->request->data['User']['action'] == "activate") {
                        $cnd = array("User.id IN ($idList) ");
                        $this->User->updateAll(array('User.status' => "'1'"), $cnd);
                        $this->Session->write('msg_type', 'alert-success');
                        $this->Session->setFlash(__('User ' . $this->request->data['User']['action'] . 'd successfully'));
                    } elseif ($this->request->data['User']['action'] == "deactivate") {
                        $cnd = array("User.id IN ($idList) ");
                        $this->User->updateAll(array('User.status' => "'0'"), $cnd);
                        $this->Session->write('msg_type', 'alert-success');
                        $this->Session->setFlash(__('User ' . $this->request->data['User']['action'] . 'd successfully'));
                    } elseif ($this->request->data['User']['action'] == "delete") {
                        $cnd = array("User.id IN ($idList) ");
                        $this->User->deleteAll($cnd);
                        $this->Session->write('msg_type', 'alert-success');
                        $this->Session->setFlash(__('User ' . $this->request->data['User']['action'] . 'd successfully'));
                    }
                }
            }
        } else {

            if ($this->Session->read('Client.keyword') && $this->Session->read('Client.keyword') != '') {
                $keyword = trim($this->Session->read('Client.keyword'));
                $this->request->data['User']['keyword'] = $keyword;
            }
			
			if ($this->Session->read('Client.date_from') && $this->Session->read('Client.date_from') != '') {
                $fromDate = trim($this->Session->read('Client.date_from'));
                $this->request->data['User']['date_from'] = $fromDate;
            }
			
			if ($this->Session->read('Client.date_to') && $this->Session->read('Client.date_to') != '') {
                $toDate = trim($this->Session->read('Client.date_to'));
                $this->request->data['User']['date_to'] = $toDate;
            }
			
			if ($this->Session->read('Client.date_range') && $this->Session->read('Client.date_range') != '') {
                $dateRange = trim($this->Session->read('Client.date_range'));
                $this->request->data['User']['date_range'] = $dateRange;
            }
			
			if ($this->Session->read('Client.country') && $this->Session->read('Client.country') != '') {
                $country = trim($this->Session->read('Client.country'));
                $this->request->data['User']['country'] = $country;
            }
        }

        if (isset($keyword) && $keyword != '') {
            $separator[] = 'keyword:' . $keyword;
            $condition[] = " 
				(
					User.first_name like '%" . $keyword . "%' OR 
					User.last_name like '%" . $keyword . "%' OR 
					User.email_address like '%" . $keyword . "%' 
				) ";
        }
		
		
		 if (!isset($dateRange) && isset($fromDate) && $fromDate!= '' &&  isset($toDate) &&  $toDate!='' ) {
            
			$separator[] = 'from_date:' . $fromDate;
			$separator[] = 'to_date:' . $toDate;
          
			$condition[] = " 
					(
						DATE_FORMAT(User.created,'%Y-%m-%d') between '" .date("Y-m-d",strtotime($fromDate)) . "' AND  '" . date("Y-m-d",strtotime($toDate)) . " '
					) ";

	     }
		 
		  if (isset($dateRange) && $dateRange != '') {
		    $dateCond = '';
			if($dateRange=='today'){
			   $dateCond = " ( DATE_FORMAT(User.created,'%Y-%m-%d') = '" .date("Y-m-d") . "' ) "; 
			}
			else if($dateRange=='week'){
			   $lastWeek = date('Y-m-d',strtotime('last Week'));  
			   $dateCond = " ( DATE_FORMAT(User.created,'%Y-%m-%d') between '" .$lastWeek . "' AND  '" . date("Y-m-d") . " ' ) "; 
			}
			else if($dateRange=='month'){
			   $lastMonth = date('Y-m-d',strtotime('last Month'));  
			   $dateCond = " ( DATE_FORMAT(User.created,'%Y-%m-%d') between '" .$lastMonth . "' AND  '" . date("Y-m-d") . " ' ) "; 
			}
			
            $separator[] = 'date_range:' . $dateRange;
			$condition[] = $dateCond;
           
         }
		  
		if (isset($country) && $country != '') {
            $separator[] = 'country:' . $country;
            $condition[] = " (	User.country ='" . $country . "' ) ";
        }

        $separator = implode("/", $separator);
        $this->set('separator', $separator);

        if (isset($this->request->data['user_search']) && $this->request->data['user_search'] == 1) {
			$this->User->recursive = -1;
            $this->paginate = array(
                'conditions' => $condition,
                'order' => 'User.id DESC',
                'limit' => 10
            );
           
		   	$userData = $this->paginate('User');
			if($userData>0){
			   foreach($userData as $key=>$ua){
			     	$ucount=$this->RestaurantsFavourites->find('count',array('conditions'=>array('RestaurantsFavourites.user_id'=>$ua['User']['id'])));
					$dishcount=$this->Dish->find('count',array('conditions'=>array('Dish.user_id'=>$ua['User']['id'])));
					$userData[$key]['User']['favouriteRestCount']=$ucount;
					$userData[$key]['User']['DishCount']=$dishcount;
			   }
			}
				
				
            $this->set('users', $userData);
        }
      
       else {
			$this->User->recursive = -1;
            $this->paginate = array(
                'conditions' => $condition,
                'order' => 'User.id DESC',
                'limit' => 10
            );
			
			$userData = $this->paginate('User');
			if($userData>0){
			   foreach($userData as $key=>$ua){
			     	$ucount=$this->RestaurantsFavourites->find('count',array('conditions'=>array('RestaurantsFavourites.user_id'=>$ua['User']['id'])));
					$dishcount=$this->Dish->find('count',array('conditions'=>array('Dish.user_id'=>$ua['User']['id'])));
					$userData[$key]['User']['favouriteRestCount']=$ucount;
					$userData[$key]['User']['DishCount']=$dishcount;
			   }
			}
				
				
            $this->set('users', $userData);
        }

    }

    public function admin_add_user(){
        $this->layout = 'admin';
		$this->loadModel('Country');
        $msgString = "";
        $leftnav = "users";
        $subleftnav = "add_user";
        $this->set(compact('leftnav','subleftnav'));
        
		$countries = $this->Country->getContryList(array('US','GB'));
		
		$this->set(compact('countries'));
        
        if ($this->request->is('post') || $this->request->is('put')) {
			
            if (empty($this->request->data["User"]["first_name"])) {
                $msgString .="Please enter your  name.<br>";
            } 
            elseif (trim($this->request->data["User"]["first_name"]) == "") {
                $msgString .= "Please enter a valid  name.<br>";
            }
            

            if (empty($this->request->data["User"]["email_address"])) {
                $msgString .="Please enter an email address.<br>";
            } 
            elseif ($this->User->checkEmail($this->request->data["User"]["email_address"]) == false) {
                $msgString .="Please enter a valid email address.<br>";
            }

            if ($this->User->isRecordUniqueemail($this->request->data["User"]["email_address"]) == false) {
                $msgString .="Email already exists.<br>";
            }
			
			if ($this->User->isRecordUniqueProfile($this->request->data["User"]["profile_name"]) == false) {
                $msgString .="Profile Name already exists.<br>";
            }

            if (empty($this->request->data["User"]["password"])) {
                $msgString .="Please provide a password.<br>";
            } 
            elseif (strlen($this->request->data["User"]["password"]) < 5) {
                $msgString .="Your password must be at least 5 characters long.<br>";
            }

            if (empty($this->request->data["User"]["confirm_password"])) {
                $msgString .="Please provide a confirm password.<br>";
            }

            $password = $this->request->data["User"]["password"];
            $conformpassword = $this->request->data["User"]["confirm_password"];

            if ($password != $conformpassword) {
                $msgString.= "Please enter the same password as above.<br>";
            }
            
           /* if (trim($this->request->data["User"]["phone_number"]) == "") {
                $msgString .= "Please enter your phone number.<br>";
            }*/
            
            /*if (trim($this->request->data["User"]["address"]) == "") {
                $msgString .= "Please enter your address.<br>";
            }
			
			if (strtotime($this->request->data["User"]["dob"]) > strtotime(date('Y-m-d')) ) {
                $msgString .= "Birth date cannot be greater than current date.<br>";
            }*/
            
            if (isset($msgString) && $msgString != '') {
                $this->Session->write('msg_type', 'alert-danger');
                $this->Session->setFlash($msgString);
            } else {

                $destination = realpath('../../app/webroot/img/uploads/users/') . '/';

              $file = $this->request->data['User']['profile_image'];

                if ($file['name']!="") {
                    $this->Upload->upload($file, $destination, null);
                    $errors = $this->Upload->errors;

                    if (empty($errors)) {
                        $this->request->data['User']['profile_image'] = $this->Upload->result;
                    } else {

                        if (is_array($errors)) {
                            $errors = implode("<br />", $errors);
                        }

                        $this->Session->write('msg_type', 'alert-danger');
                        $this->Session->setFlash($errors);
						return;
                        /* $this->redirect(array('admin' => true, 'controller' => 'users', 'action' => 'add_user'));
                        exit(); */
                    }
                } 
                else {
                    unset($this->request->data['User']['profile_image']);
                }

                $this->request->data['User']['username'] = $this->request->data['User']['email_address'];
                $this->request->data['User']['role_id'] = '2';
				
                $password = $this->request->data['User']['password'];
				$this->request->data['User']['password'] = AuthComponent::password($this->request->data['User']['password']);
				//prd($this->request->data);
                if ($this->User->save($this->request->data)) {

                    // start mail code
                    
                    $email_template_detail = $this->EmailTemplate->find('first', array('conditions' => array('EmailTemplate.email_type' => 'admin_registration')));

                    $email_template = $email_template_detail['EmailTemplate']['message'];
                  

                    $email_template = str_replace('[site_title]', Configure::read('Site.title'), $email_template);
                    //$email_template = str_replace('[username]', $this->request->data['User']['first_name'] . ' ' . $this->request->data['User']['last_name'], $email_template);
		     $email_template = str_replace('[username]', $this->request->data['User']['first_name'] , $email_template);
                    $email_template = str_replace('[email]', $this->request->data['User']['email_address'], $email_template);
                    $email_template = str_replace('[password]', $password, $email_template);

                    
                 
                    
                    	                $to = $this->request->data['User']['email_address'];
					$subject = $email_template_detail['EmailTemplate']['subject'];
					$message = $email_template;
					$from =  $email_template_detail['EmailTemplate']['sender_email'];
					$fromName =$email_template_detail['EmailTemplate']['sender_name'];
					$delivery = 'smtp';
					$replyTo = $email_template_detail['EmailTemplate']['sender_email'];
					$replyName = $email_template_detail['EmailTemplate']['sender_name'];
                    $bcc = array();
                    $template = 'default';
                    $sendAs = 'html';
                    
                    
                    
                    $this->_send_mail($to, $subject, $message, $from, $fromName, $delivery, $replyTo, $replyName, $bcc, $template, $sendAs);
                    
                    $this->Session->write('msg_type', 'alert-success');
                    $this->Session->setFlash(__('The user has been saved'));
                    $this->redirect(array('admin' => true, 'controller' => 'users', 'action' => 'index'));
                }
            }
        }
    }
	
    public function admin_edit_user($id = null,$redirect=null){
        $this->layout = 'admin';
		$this->loadModel('Country');
        $msgString = "";
        $leftnav = "users";
        $subleftnav = "add_user";
        $this->set(compact('leftnav','subleftnav'));
        
		$this->set('countries', $this->Country->getContryList());
		$this->set('redirect', $redirect);
        
        if (empty($id) && empty($this->request->data)) {
            $this->Session->write('msg_type', 'alert-danger');
            $this->Session->setFlash(__('Invalid User'));
            $this->redirect(array('admin' => true, 'controller' => 'users', 'action' => 'index'));
        }

        if ($this->request->is('post') || $this->request->is('put')) {
			
            if (empty($this->request->data["User"]["first_name"])) {
                $msgString .="Please enter your  name.<br>";
            } 
            elseif (trim($this->request->data["User"]["first_name"]) == "") {
                $msgString .= "Please enter a valid  name.<br>";
            }
           
			

            if (empty($this->request->data["User"]["email_address"])) {
                $msgString .="Please enter an email address.<br>";
            } 
            elseif ($this->User->checkEmail($this->request->data["User"]["email_address"]) == false) {
                $msgString .="Please enter a valid email address.<br>";
            }

            if ($this->request->data["User"]["email_address"] != $this->request->data["User"]["old_email_address"]) {
                if ($this->User->isRecordUniqueemail($this->request->data["User"]["email_address"]) == false) {
                    $msgString .="Email already exists.<br>";
                }
            }
            
			if ($this->request->data["User"]["profile_name"] != $this->request->data["User"]["old_profile_name"]) {
				if ($this->User->isRecordUniqueProfile($this->request->data["User"]["profile_name"]) == false) {
					$msgString .="Profile Name already exists.<br>";
				}
			}
			
          /*  if (trim($this->request->data["User"]["phone_number"]) == "") {
                $msgString .= "Please enter your phone number.<br>";
            }*/
            
          
            
            if (isset($msgString) && $msgString != '') {
                $this->Session->write('msg_type', 'alert-danger');
                $this->Session->setFlash($msgString);
            } else {
                $destination = realpath('../../app/webroot/img/uploads/users/') . '/';

                $file = $this->request->data['User']['profile_image'];

                if (!empty($file['name'])) {
                    $this->Upload->upload($file, $destination, null);
                    $errors = $this->Upload->errors;

                    if (empty($errors)) {
                        $this->request->data['User']['profile_image'] = $this->Upload->result;
						
						// remove old image start
								$destination = realpath('../../app/webroot/img/uploads/users/') . '/';
								$userfile = $this->request->data['User']['old_profile_image'];
								if($userfile!=""){
									
									if(file_exists($destination.$userfile)){
										unlink($destination.$userfile);
									}	
								}	
						
						// remove old image end 
                    } else {

                        if (is_array($errors)) {
                            $errors = implode("<br />", $errors);
                        }

                        $this->Session->write('msg_type', 'alert-danger');
                        $this->Session->setFlash($errors);
                        $this->redirect(array('admin' => true, 'controller' => 'users', 'action' => 'edit_user', $this->request->data['User']['id']));
                        exit();
                    }
                } else {
                    unset($this->request->data['User']['profile_image']);
                }

                $this->request->data['User']['username'] = $this->request->data['User']['email_address'];

                if ($this->User->save($this->request->data)) {
                    $this->Session->write('msg_type', 'alert-success');
                    $this->Session->setFlash(__('The user has been updated'));
					if($redirect==1){
					  $this->redirect(array('admin' => true, 'controller' => 'reports', 'action' => 'report_user'));
					}else{
						$this->redirect(array('admin' => true, 'controller' => 'users', 'action' => 'index'));
					}
                }
            }
        } else {

            $this->User->id = $id;

            if (!$this->User->exists()) {
                $this->Session->write('msg_type', 'alert-danger');
                $this->Session->setFlash(__('Invalid User'));
                $this->redirect(array('admin' => true, 'controller' => 'users', 'action' => 'index'));
            }

            $this->request->data = $this->User->read(null, $id);
			$this->set('id', $id);	
            unset($this->request->data['User']['password']);
            $this->request->data['User']['old_email_address'] = $this->request->data['User']['email_address'];
			$this->request->data['User']['old_profile_image'] = $this->request->data['User']['profile_image'];
        }
		
    }
  
    public function admin_delete_user($id){

        $user = $this->User->find('first', array('conditions' => array('User.id' => $id), 'fields' => array('User.id')));

        if (!empty($user) && $this->User->delete($user['User']['id'])) {
            $this->Session->write('msg_type', 'alert-success');
            $this->Session->setFlash(__('User deleted successfully.'));
            $this->redirect(array('admin' => true, 'controller' => 'users', 'action' => 'index'));
        } 
        else {
            $this->Session->write('msg_type', 'alert-danger');
            $this->Session->setFlash(__('You are not authorized to access this record.'));
            $this->redirect(array('admin' => true, 'controller' => 'users', 'action' => 'index'));
        }
    }
	
	 public function admin_delete_image($id){

        $user = $this->User->find('first', array('conditions' => array('User.id' => $id), 'fields' => array('User.id','User.profile_image')));
		
		$this->User->id = $id;
		//$this->User->saveField('profile_image', '');

        if (!empty($user) && $this->User->saveField('profile_image', '')) {
		
			// remove  image start
			 
								$destination = realpath('../../app/webroot/img/uploads/users/') . '/';
								$userfile = $user['User']['profile_image'];
								if($userfile!=""){
									
									if(file_exists($destination.$userfile)){
										unlink($destination.$userfile);
									}	
								}	
						
		    // remove  image end 
		
		
            $this->Session->write('msg_type', 'alert-success');
            $this->Session->setFlash(__('User image deleted successfully.'));
             $this->redirect(array('admin' => true, 'controller' => 'users', 'action' => 'edit_user', $id));
        } 
        else {
            $this->Session->write('msg_type', 'alert-danger');
            $this->Session->setFlash(__('You are not authorized to access this record.'));
            $this->redirect(array('admin' => true, 'controller' => 'users', 'action' => 'edit_user', $id));
        }
    }

    public function admin_logout() {
        $this->Auth->logout();
        $this->redirect(array('admin' => true, 'controller' => 'users', 'action' => 'login'));
    }
    
  
    public function admin_get_user_name($user_id){
        $user = $this->User->find('first', array('conditions' => array('User.id' => $user_id), 'fields' => array('User.first_name','User.last_name')));
        return $user['User']['first_name'].' '.$user['User']['last_name'];        
    }
    
    public function admin_get_user_detail($user_id){
        $user = $this->User->find('first', array('conditions' => array('User.id' => $user_id)));
        return $user['User'];        
    }
    
    public function get_user_name($user_id){
        $user = $this->User->find('first', array('conditions' => array('User.id' => $user_id), 'fields' => array('User.first_name','User.last_name')));
        return $user['User']['first_name'].' '.$user['User']['last_name'];        
    }
    
    public function get_user_detail($user_id){
        $user = $this->User->find('first', array('conditions' => array('User.id' => $user_id)));
        return $user['User'];        
    }
    
    public function logout() {
        $this->Auth->logout();
        $this->redirect(array('controller' => 'indexs', 'action' => 'index'));
    }
  
        
	public function check_unique_email(){
		$this->layout = 'plain';
		$email = $this->request->data['User']['email_address'];
		if($this->User->isRecordUniqueemail($email)){
			echo 'true';
		}else{
			echo 'false';
		}
		die;
	}
	
	public function process(){
		$this->layout = 'plain';
		$captcha = $this->request->data['User']['captcha'];
		if($captcha == $this->Session->read('security_code')){
			echo 'true';
		}else{
			echo 'false';
		}
		die;
	}
	
	function activate($user_id=null, $code=null){
	$this->layout = 'plain';
	  
		if( empty($user_id) || empty($code) ){
			$this->Session->setFlash( "Invalid URL!",'front/flash_warning');
			$this->redirect(array('controller'=>'users','action'=>'account_error'));
		}

		$user_record = $this->User->find('first', array(
			'conditions' => array(
				'User.id' => $user_id,
				'User.reset_code' => $code
			),
			'recursive'=>-1
		));
	// echo "<pre>";
	// print_r($user_record);
	// die();
		if( !empty($user_record) ){
			$this->request->data['User']['id'] = $user_record['User']['id'];
			$this->request->data['User']['status'] = 1;
			$location = @$this->General->getAllDetailByIp('US',FALSE);
			$countryName = @$location['country'];
			$statelist = @$location['state'];
			$citylist = @$location['city'];
			if(!empty($countryName)){
				$this->request->data['User']['country'] = $countryName;
			}
			if(!empty($statelist) && $statelist!='none'){
				$this->request->data['User']['state'] = $statelist;
			}
			if(!empty($citylist) && $citylist!='none'){
				$this->request->data['User']['city'] = $citylist;
			}			
			$this->request->data['User']['reset_code'] = 0;
			
			if($this->User->save($this->request->data['User'])){
				$this->Auth->autoRedirect = false;				
				$this->Auth->login($user_record['User']);
				$this->Session->setFlash( __d('activate_account',"You have successfully activated your dish-out account."),'front/flash_success');
				$this->redirect(array('controller' => 'users', 'action' => 'welcome'));
			}
		}else{
			$this->Session->setFlash( __d('activate_account',"Sorry you can not activate your account, either link expired or invalid."),'front/flash_error');
			$this->redirect(array('controller' => 'users', 'action' => 'account_error'));
		}
		
		//$this->redirect(array('controller' => 'indexs', 'action' => 'index'));
	}
	
	function welcome(){
			$this->layout = 'plain';
	}
	
	function account_error(){
			$this->layout = 'plain';
	}
	
	public function fill_states($showSpan=null){
		$this->layout = 'plain';
		$this->loadModel('State');
		$stateCondition = array();
		$states=null;
		if(isset($this->request->data['country_code']) && !empty($this->request->data['country_code']) ){
			$stateCondition[] = array('State.country_id'=>$this->request->data['country_code']);
			$states = $this->State->getStateListByCountryId($this->request->data['country_code']);
		}
		//prd($states);
		$this->set(compact('states','showSpan'));
	}
	
	public function get_encrypt($text){
		echo $this->General->encrypt_text($text);
		die;
	}
	
	public function get_decrypt($text){
		echo $this->General->decrypt_text($text);
		die;
	}
	public function testgit()
	{
		$a =45;
                $b =96;
                
                try
                { 
                    $d=$a+$b;
                   
                    
                }
                catch(Exception $e)
                {
                  echo 'Caught Exception'.$e.getMessage();   
                }
				
				echo 'this is test functionss';
                
	}
	
	
	
}