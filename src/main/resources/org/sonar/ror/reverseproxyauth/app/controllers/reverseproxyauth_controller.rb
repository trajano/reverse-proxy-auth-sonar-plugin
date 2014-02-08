class ReverseproxyauthController < ApplicationController
	skip_before_filter :check_authentication
	def validate
		self.current_user = User.authenticate(nil, nil, servlet_request)
		redirect_back_or_default(home_url)
	end
end
