jQuery(function($){
    function h(e) {
        $(e).css({'height':'auto','overflow-y':'hidden'}).height(e.scrollHeight);
    }
    $('textarea').each(function () {
        h(this);
    }).on('input', function () {
        h(this);
    });
    $(document).ready(function(){
        setTimeout(function(){
            $('.success').fadeOut(1000);
        }, 4000);

        $('.first_name, .last_name').each(function(){
            if ( $(this).text() == "None" ) {
                $(this).text('');
            }
        });

        $('.user_image img, img.user_image').each(function(){
            if ( $(this).attr('src').length == 0 || $(this).attr('src') == "None" ) {
                $(this).attr('src','/static/images/placeholder.png');
            }
        });
    });
});